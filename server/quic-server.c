#include "contiki.h"
#include "net/ipv6/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/uip-udp-packet.h"
#include "sys/log.h"
#include "quic-lite.h"
#include "contiki-dtls.h"
#include "lib/random.h"
#include "sys/ctimer.h"
#include "project-conf.h"
#include "net/ipv6/simple-udp.h"
#include <inttypes.h>
#include <string.h>

/* Logging Configuration */
#define LOG_MODULE "QUIC-Server"
#define LOG_LEVEL LOG_LEVEL_INFO

/* QUIC Configuration */
#define MAX_STREAMS 10
#define INITIAL_WINDOW_SIZE 2048
#define MAX_RETRIES 3
#define MAX_ACK_RANGE 5
#define STREAM_TIMEOUT (CLOCK_SECOND * 30)
#define ACK_DELAY_THRESHOLD 2

/* Connection States */
typedef enum {
  QUIC_STATE_INIT,
  QUIC_STATE_HANDSHAKE,
  QUIC_STATE_ACTIVE,
  QUIC_STATE_CLOSING,
  QUIC_STATE_CLOSED
} quic_state_t;

/* Stream States */
typedef enum {
  STREAM_CLOSED,
  STREAM_OPEN,
  STREAM_HALF_CLOSED
} stream_state_t;

/* ACK Frame Structure */
typedef struct {
  uint32_t largest_acked;
  uint32_t ack_delay;
  uint32_t first_ack_range;
  uint32_t ack_ranges[MAX_ACK_RANGE];
  uint8_t num_ack_ranges;
} quic_ack_frame_t;

/* Stream State */
typedef struct {
  uint16_t stream_id;
  uint32_t read_offset;
  uint32_t write_offset;
  uint32_t max_data;
  stream_state_t state;
  struct ctimer timeout;
} quic_stream_t;

/* Packet Queue Entry */
typedef struct {
  uint8_t data[MAX_BUFFER_LEN];
  uint16_t len;
  uint32_t packet_number;
  struct ctimer timer;
  clock_time_t send_time;
  uint8_t retry_count;
} quic_packet_t;

/* Connection Context */
typedef struct {
  uip_ipaddr_t client_addr;
  uint16_t client_port;
  uint8_t connection_id;
  quic_state_t state;
  
  /* Reliability */
  uint32_t next_packet_number;
  uint32_t largest_received_packet;
  quic_packet_t pending_packets[8];
  uint8_t packet_head;
  uint8_t packet_tail;
  
  /* Stream Management */
  quic_stream_t streams[MAX_STREAMS];
  uint16_t next_stream_id;
  
  /* Flow Control */
  uint32_t flow_control_window;
  
  /* RTT Estimation */
  clock_time_t smoothed_rtt;
  clock_time_t rtt_variance;
  clock_time_t min_rtt;
} quic_connection_t;

static struct simple_udp_connection udp_conn;
static quic_connection_t active_connection;
static dtls_context_t *dtls_ctx;
static uint8_t buffer[MAX_BUFFER_LEN];

/* Utility Functions */
static size_t decode_varint(uint8_t *in, uint32_t *val) {
  if(*in < 0x40) {
    *val = *in;
    return 1;
  } else if(*in < 0x80) {
    *val = ((*in & 0x3F) << 8) | in[1];
    return 2;
  } else {
    *val = ((*in & 0x3F) << 16) | (in[1] << 8) | in[2];
    return 3;
  }
}

static int decode_ack_frame(uint8_t *data, size_t len, quic_ack_frame_t *ack) {
  uint8_t *p = data;
  uint32_t temp_val;
  
  if(*p++ != 0x02) return -1;
  
  p += decode_varint(p, &ack->largest_acked);
  p += decode_varint(p, &ack->ack_delay);
  p += decode_varint(p, &temp_val);
  ack->num_ack_ranges = (uint8_t)temp_val;
  p += decode_varint(p, &ack->first_ack_range);
  
  for(int i = 0; i < ack->num_ack_ranges && i < MAX_ACK_RANGE; i++) {
    p += decode_varint(p, &ack->ack_ranges[i]);
  }
  
  return p - data;
}

static void update_rtt_estimate(clock_time_t rtt_sample) {
  if(active_connection.min_rtt == 0 || rtt_sample < active_connection.min_rtt) {
    active_connection.min_rtt = rtt_sample;
  }
  
  if(active_connection.smoothed_rtt == 0) {
    active_connection.smoothed_rtt = rtt_sample;
    active_connection.rtt_variance = rtt_sample / 2;
  } else {
    clock_time_t delta = active_connection.smoothed_rtt - rtt_sample;
    active_connection.rtt_variance = (3 * active_connection.rtt_variance + ABS(delta)) / 4;
    active_connection.smoothed_rtt = (7 * active_connection.smoothed_rtt + rtt_sample) / 8;
  }
}

/* ACK Handling */
static void send_ack(uint32_t packet_number) {
  quic_header_t hdr = {
    .packet_type = PACKET_TYPE_1RTT,
    .connection_id = active_connection.connection_id,
    .packet_number = active_connection.next_packet_number++,
    .stream_id = 0
  };
  
  quic_ack_frame_t ack = {
    .largest_acked = packet_number,
    .ack_delay = 0,
    .first_ack_range = 0,
    .num_ack_ranges = 0
  };
  
  uint8_t len = encode_quic_packet(&hdr, (uint8_t*)&ack, sizeof(ack), buffer);
  simple_udp_sendto(&udp_conn, buffer, len, &active_connection.client_addr);
}

static void handle_ack_frame(quic_ack_frame_t *ack) {
  for(int i = 0; i < ack->num_ack_ranges; i++) {
    if(ack->ack_ranges[i] == active_connection.pending_packets[active_connection.packet_head].packet_number) {
      clock_time_t rtt = clock_time() - active_connection.pending_packets[active_connection.packet_head].send_time;
      update_rtt_estimate(rtt);
      ctimer_stop(&active_connection.pending_packets[active_connection.packet_head].timer);
      active_connection.packet_head = (active_connection.packet_head + 1) % 8;
    }
  }
  
  /* Congestion control */
  if(ack->ack_delay > active_connection.smoothed_rtt * ACK_DELAY_THRESHOLD) {
    active_connection.flow_control_window = MAX(INITIAL_WINDOW_SIZE/2, 
                                             active_connection.flow_control_window * 3/4);
  } else {
    active_connection.flow_control_window = MIN(INITIAL_WINDOW_SIZE * 2,
                                             active_connection.flow_control_window + 1024);
  }
}

/* Packet Management */
static void retry_packet(void *ptr) {
  quic_packet_t *pkt = (quic_packet_t *)ptr;
  
  if(pkt->retry_count < MAX_RETRIES && active_connection.state < QUIC_STATE_CLOSING) {
    pkt->retry_count++;
    simple_udp_sendto(&udp_conn, pkt->data, pkt->len, &active_connection.client_addr);
    ctimer_restart(&pkt->timer);
  } else {
    active_connection.state = QUIC_STATE_CLOSING;
  }
}

static void queue_packet(uint8_t *data, uint16_t len, uint32_t pn) {
  if((active_connection.packet_tail + 1) % 8 == active_connection.packet_head) {
    return;
  }
  
  memcpy(active_connection.pending_packets[active_connection.packet_tail].data, data, len);
  active_connection.pending_packets[active_connection.packet_tail].len = len;
  active_connection.pending_packets[active_connection.packet_tail].packet_number = pn;
  active_connection.pending_packets[active_connection.packet_tail].send_time = clock_time();
  active_connection.pending_packets[active_connection.packet_tail].retry_count = 0;
  
  ctimer_set(&active_connection.pending_packets[active_connection.packet_tail].timer,
             active_connection.smoothed_rtt ? active_connection.smoothed_rtt * 2 : CLOCK_SECOND,
             retry_packet, &active_connection.pending_packets[active_connection.packet_tail]);
  
  active_connection.packet_tail = (active_connection.packet_tail + 1) % 8;
}

/* Stream Management */
static void stream_timeout(void *stream_ptr) {
  quic_stream_t *stream = (quic_stream_t *)stream_ptr;
  stream->state = STREAM_CLOSED;
}

static quic_stream_t *open_stream(uint16_t stream_id) {
  for(int i = 0; i < MAX_STREAMS; i++) {
    if(active_connection.streams[i].state == STREAM_CLOSED) {
      active_connection.streams[i].stream_id = stream_id;
      active_connection.streams[i].state = STREAM_OPEN;
      active_connection.streams[i].read_offset = 0;
      active_connection.streams[i].write_offset = 0;
      active_connection.streams[i].max_data = INITIAL_WINDOW_SIZE;
      ctimer_set(&active_connection.streams[i].timeout, STREAM_TIMEOUT, stream_timeout, &active_connection.streams[i]);
      return &active_connection.streams[i];
    }
  }
  return NULL;
}

/* DTLS Handlers */
static int send_to_peer(dtls_context_t *ctx, dtls_session_t *session, 
                       uint8_t *data, size_t len) {
  quic_header_t hdr = {
    .packet_type = (active_connection.state == QUIC_STATE_HANDSHAKE) ? PACKET_TYPE_HANDSHAKE : PACKET_TYPE_1RTT,
    .connection_id = active_connection.connection_id,
    .packet_number = active_connection.next_packet_number,
    .stream_id = 0
  };
  
  uint8_t pkt_len = encode_quic_packet(&hdr, data, len, buffer);
  
  if(active_connection.state == QUIC_STATE_HANDSHAKE) {
    queue_packet(buffer, pkt_len, active_connection.next_packet_number);
  }
  
  simple_udp_sendto(&udp_conn, buffer, pkt_len, &active_connection.client_addr);
  active_connection.next_packet_number++;
  
  return len;
}

static int read_from_peer(dtls_context_t *ctx, dtls_session_t *session,
                         uint8_t *data, size_t len) {
  if(active_connection.state == QUIC_STATE_HANDSHAKE) {
    active_connection.state = QUIC_STATE_ACTIVE;
    /* Clear retransmission queue */
    while(active_connection.packet_head != active_connection.packet_tail) {
      ctimer_stop(&active_connection.pending_packets[active_connection.packet_head].timer);
      active_connection.packet_head = (active_connection.packet_head + 1) % 8;
    }
  }
  return 0;
}

static int get_psk_info(dtls_context_t *ctx, dtls_session_t *session,
                       const uint8_t *id, size_t id_len,
                       uint8_t *result, size_t result_len) {
  const char psk[] = "secretPSK";
  if(result_len < strlen(psk)) return -1;
  memcpy(result, psk, strlen(psk));
  return strlen(psk);
}

/* Connection Management */
static void send_handshake_response() {
  dtls_session_t session;
  memset(&session, 0, sizeof(session));
  uip_ipaddr_copy(&session.addr, &active_connection.client_addr);
  session.port = UIP_HTONS(active_connection.client_port);
  session.size = sizeof(uip_ipaddr_t);

  /* Start DTLS handshake */
  if(dtls_connect(dtls_ctx, &session) < 0) {
    LOG_ERR("DTLS connect failed\n");
    return;
  }

  /* Also send QUIC handshake packet */
  quic_header_t hdr = {
    .packet_type = PACKET_TYPE_HANDSHAKE,
    .connection_id = active_connection.connection_id,
    .packet_number = active_connection.next_packet_number,
    .stream_id = 0
  };
  
  uint8_t payload[] = "QUIC Handshake Response";
  uint8_t len = encode_quic_packet(&hdr, payload, sizeof(payload), buffer);
  
  queue_packet(buffer, len, active_connection.next_packet_number);
  simple_udp_sendto(&udp_conn, buffer, len, &active_connection.client_addr);
  active_connection.next_packet_number++;
}

static void send_stream_data(uint16_t stream_id, const char *data) {
  quic_header_t hdr = {
    .packet_type = PACKET_TYPE_1RTT,
    .connection_id = active_connection.connection_id,
    .packet_number = active_connection.next_packet_number,
    .stream_id = stream_id
  };
  
  uint8_t len = encode_quic_packet(&hdr, (uint8_t *)data, strlen(data)+1, buffer);
  simple_udp_sendto(&udp_conn, buffer, len, &active_connection.client_addr);
  active_connection.next_packet_number++;
}

static void handle_stream_data(quic_stream_t *stream, uint8_t *data, uint16_t len) {
  char response[MAX_BUFFER_LEN];
  snprintf(response, sizeof(response), "ACK:%.*s", len, data);
  send_stream_data(stream->stream_id, response);
}

/* UDP Packet Handler */
static void udp_handler(struct simple_udp_connection *c,
                       const uip_ipaddr_t *sender_addr,
                       uint16_t sender_port,
                       const uip_ipaddr_t *receiver_addr,
                       uint16_t receiver_port,
                       const uint8_t *data,
                       uint16_t datalen) {
  /* Initialize connection if first packet */
  if(active_connection.state == QUIC_STATE_INIT) {
    uip_ipaddr_copy(&active_connection.client_addr, sender_addr);
    active_connection.client_port = sender_port;
    active_connection.connection_id = 0x01;
    active_connection.state = QUIC_STATE_HANDSHAKE;
    active_connection.flow_control_window = INITIAL_WINDOW_SIZE;
    active_connection.next_stream_id = 1;
    
    /* Initialize DTLS */
    dtls_ctx = dtls_new_context();
    if(!dtls_ctx) {
      LOG_ERR("Failed to create DTLS context\n");
      return;
    }

    dtls_ctx->app_data = &active_connection;
    dtls_ctx->handler.write = send_to_peer;
    dtls_ctx->handler.read = read_from_peer;
    dtls_ctx->handler.get_psk_info = get_psk_info;
    
    send_handshake_response();
    return;
  }
  
  quic_header_t hdr;
  if(decode_quic_packet((uint8_t *)data, datalen, &hdr) > 0) {
    /* Immediately acknowledge the packet */
    send_ack(hdr.packet_number);
    
    if(hdr.packet_type == PACKET_TYPE_HANDSHAKE || 
       hdr.packet_type == PACKET_TYPE_1RTT) {
      if(dtls_ctx) {
        dtls_session_t session;
        session.size = sizeof(uip_ipaddr_t);
        uip_ipaddr_copy(&session.addr, sender_addr);
        session.port = UIP_HTONS(sender_port);
        
        dtls_handle_message(dtls_ctx, &session, 
                          (uint8_t *)(data + QUIC_HEADER_LEN), 
                          datalen - QUIC_HEADER_LEN);
      }
      
      /* Handle application data on streams */
      if(hdr.stream_id > 0 && active_connection.state == QUIC_STATE_ACTIVE) {
        quic_stream_t *stream = NULL;
        for(int i = 0; i < MAX_STREAMS; i++) {
          if(active_connection.streams[i].stream_id == hdr.stream_id) {
            stream = &active_connection.streams[i];
            break;
          }
        }
        
        if(!stream) {
          stream = open_stream(hdr.stream_id);
        }
        
        if(stream) {
          ctimer_restart(&stream->timeout);
          handle_stream_data(stream, (uint8_t *)(data + QUIC_HEADER_LEN), 
                            datalen - QUIC_HEADER_LEN);
        }
      }
    } 
    else if(hdr.packet_type == PACKET_TYPE_RETRY) {
      quic_ack_frame_t ack;
      if(decode_ack_frame((uint8_t *)(data + QUIC_HEADER_LEN), 
                         datalen - QUIC_HEADER_LEN, &ack) > 0) {
        handle_ack_frame(&ack);
      }
    }
  }
}

/* Main Process */
PROCESS(quic_server_process, "QUIC Server");
AUTOSTART_PROCESSES(&quic_server_process);

PROCESS_THREAD(quic_server_process, ev, data) {
  PROCESS_BEGIN();

  /* Initialize connection state */
  memset(&active_connection, 0, sizeof(active_connection));
  active_connection.state = QUIC_STATE_INIT;
  active_connection.connection_id = 0x01;
  
  /* Register UDP handler */
  simple_udp_register(&udp_conn, QUIC_SERVER_PORT, NULL, QUIC_CLIENT_PORT, udp_handler);
  
  LOG_INFO("QUIC Server started on port %d with %d streams\n", 
          QUIC_SERVER_PORT, MAX_STREAMS);

  while(1) {
    PROCESS_YIELD();
    
    if(active_connection.state == QUIC_STATE_CLOSING) {
      if(dtls_ctx) {
        dtls_free_context(dtls_ctx);
        dtls_ctx = NULL;
      }
      LOG_INFO("Connection closed\n");
      active_connection.state = QUIC_STATE_INIT;
    }
  }

  PROCESS_END();
}
