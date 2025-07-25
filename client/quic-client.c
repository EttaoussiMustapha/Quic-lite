#include "contiki.h"
#include "net/ipv6/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/uip-udp-packet.h"
#include "sys/log.h"
#include "quic-lite.h"
#include "contiki-dtls.h"
#include "lib/random.h"
#include "sys/ctimer.h"
#include "sys/energest.h"
#include "project-conf.h"
#include "net/ipv6/simple-udp.h"
#include <inttypes.h>
#include <string.h>

/* Configuration */
#define SERVER_PORT QUIC_SERVER_PORT
#define CLIENT_PORT QUIC_CLIENT_PORT
#define SERVER_ADDR "fe80::202:2:2:2"
#define INITIAL_CID 0x01
#define MAX_RETRIES 3
#define CONNECTION_TIMEOUT (CLOCK_SECOND * QUIC_CONNECTION_TIMEOUT)
#define RETRY_TIMEOUT (CLOCK_SECOND * QUIC_RETRY_TIMEOUT)
#define MAX_ACK_RANGE 5
#define INITIAL_WINDOW_SIZE 2048
#define MAX_STREAMS 100
#define STREAM_TIMEOUT (CLOCK_SECOND)
#define MIN_RTT_ESTIMATE (CLOCK_SECOND / 10)
#define MAX_RTT_ESTIMATE (CLOCK_SECOND * 2)
#define ENERGETIC_REPORT_INTERVAL (CLOCK_SECOND / 10)
#define PACKET_COUNTER_RESET_INTERVAL (CLOCK_SECOND * 60)

/* Congestion Control Parameters */
#define CC_INITIAL_WINDOW     (2 * INITIAL_WINDOW_SIZE)
#define CC_MIN_WINDOW         (INITIAL_WINDOW_SIZE)
#define CC_MAX_WINDOW         (10 * INITIAL_WINDOW_SIZE)
#define CC_FAST_RETRANS_THRESH 3
#define CC_ALPHA              0.125
#define CC_BETA               0.25

#define LOG_MODULE "QUIC-Client"
#define LOG_LEVEL LOG_LEVEL_INFO

void print_energy_consumption() {
  energest_flush();

  unsigned long cpu = energest_type_time(ENERGEST_TYPE_CPU);
  unsigned long lpm = energest_type_time(ENERGEST_TYPE_LPM);
  unsigned long tx = energest_type_time(ENERGEST_TYPE_TRANSMIT);
  unsigned long rx = energest_type_time(ENERGEST_TYPE_LISTEN);

  double cpu_time = (double)cpu / RTIMER_SECOND;
  double lpm_time = (double)lpm / RTIMER_SECOND;
  double tx_time = (double)tx / RTIMER_SECOND;
  double rx_time = (double)rx / RTIMER_SECOND;

  double voltage = 3.0;
  double E_cpu = voltage * 0.0018 * cpu_time * 1000.0;
  double E_lpm = voltage * 0.0000545 * lpm_time * 1000.0;
  double E_tx = voltage * 0.0174 * tx_time * 1000.0;
  double E_rx = voltage * 0.0188 * rx_time * 1000.0;

  printf("Energy (mJ): CPU=%.3f, LPM=%.3f, TX=%.3f, RX=%.3f, TOTAL=%.3f\n",
         E_cpu, E_lpm, E_tx, E_rx, E_cpu + E_lpm + E_tx + E_rx);
}

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
  STREAM_HALF_CLOSED_LOCAL,
  STREAM_HALF_CLOSED_REMOTE,
  STREAM_RESET
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
  struct ctimer timeout_timer;
  uint8_t in_use;
} quic_stream_t;

/* Packet Queue Entry */
typedef struct {
  uint8_t data[MAX_BUFFER_LEN];
  uint16_t len;
  uint32_t packet_number;
  struct ctimer timer;
  clock_time_t send_time;
} quic_packet_t;

/* Global Connection State */
typedef struct {
  struct simple_udp_connection udp_conn;
  dtls_context_t *dtls_ctx;
  dtls_session_t dtls_session;
  quic_state_t state;
  uint8_t connection_id;
  
  /* Reliability Features */
  uint32_t largest_acked_packet;
  uint32_t next_packet_number;
  uint32_t largest_received_packet;
  quic_packet_t pending_packets[4];
  uint8_t packet_head;
  uint8_t packet_tail;
  
  /* Stream Management */
  quic_stream_t streams[MAX_STREAMS];
  uint32_t flow_control_window;
  
  /* RTT Estimation */
  clock_time_t smoothed_rtt;
  clock_time_t rtt_variance;
  clock_time_t min_rtt;
  clock_time_t latest_rtt;
  
  /* Timers */
  struct etimer retry_timer;
  struct etimer data_timer;
  struct etimer energest_timer;
  struct etimer packet_counter_timer;
  uint8_t retry_count;
  uint8_t handshake_complete;
  
  /* Enhanced Metrics */
  uint32_t total_packets_sent;
  uint32_t total_packets_received;
  uint32_t total_bytes_sent;
  uint32_t total_bytes_received;
  uint32_t current_stream_cycle;
  
  /* Congestion Control */
  uint32_t cwnd;
  uint32_t ssthresh;
  uint32_t bytes_in_flight;
  uint8_t dup_ack_count;
  uint32_t recovery_pn;
} quic_client_t;

static quic_client_t client;
static uint8_t buffer[MAX_BUFFER_LEN];

/* Forward declarations */
static void udp_handler(struct simple_udp_connection *c,
                       const uip_ipaddr_t *sender_addr,
                       uint16_t sender_port,
                       const uip_ipaddr_t *receiver_addr,
                       uint16_t receiver_port,
                       const uint8_t *data,
                       uint16_t datalen);
static void stream_timeout_handler(void *stream_ptr);
static void reset_packet_counter(void *ptr);
static void retry_packet(void *ptr);

/* Congestion Control Functions */
static void cc_init() {
  client.cwnd = CC_INITIAL_WINDOW;
  client.ssthresh = UINT32_MAX;
  client.bytes_in_flight = 0;
  client.dup_ack_count = 0;
  client.recovery_pn = 0;
}

static void cc_on_packet_sent(uint32_t pn, size_t len) {
  client.bytes_in_flight += len;
  LOG_DBG("CC: Packet %"PRIu32" sent, cwnd=%"PRIu32", in_flight=%"PRIu32"\n",
         pn, client.cwnd, client.bytes_in_flight);
}

static void cc_on_ack(uint32_t acked_pn, uint32_t bytes_acked) {
  if(acked_pn <= client.recovery_pn) {
    return;
  }

  if(client.cwnd < client.ssthresh) {
    client.cwnd += bytes_acked;
    LOG_DBG("CC: Slow Start, cwnd=%"PRIu32"\n", client.cwnd);
  } else {
    client.cwnd += (INITIAL_WINDOW_SIZE * INITIAL_WINDOW_SIZE) / client.cwnd;
    LOG_DBG("CC: Congestion Avoidance, cwnd=%"PRIu32"\n", client.cwnd);
  }

  client.bytes_in_flight -= bytes_acked;
}

static void cc_on_loss(uint32_t lost_pn) {
  client.ssthresh = MAX(client.cwnd / 2, CC_MIN_WINDOW);
  client.cwnd = CC_MIN_WINDOW;
  client.recovery_pn = client.next_packet_number;
  LOG_WARN("CC: Congestion! New cwnd=%"PRIu32", ssthresh=%"PRIu32"\n",
          client.cwnd, client.ssthresh);
}

static void cc_on_dup_ack(uint32_t pn) {
  client.dup_ack_count++;
  
  if(client.dup_ack_count == CC_FAST_RETRANS_THRESH) {
    LOG_DBG("CC: Fast Retransmit triggered for pn %"PRIu32"\n", pn);
    cc_on_loss(pn);
    retry_packet(&client.pending_packets[client.packet_head]);
  }
}

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
  
  p += decode_varint(p, &temp_val);
  ack->largest_acked = temp_val;
  
  p += decode_varint(p, &temp_val);
  ack->ack_delay = temp_val;
  
  p += decode_varint(p, &temp_val);
  ack->num_ack_ranges = (uint8_t)temp_val;
  
  p += decode_varint(p, &temp_val);
  ack->first_ack_range = temp_val;
  
  for(int i = 0; i < ack->num_ack_ranges && i < MAX_ACK_RANGE; i++) {
    p += decode_varint(p, &temp_val);
    ack->ack_ranges[i] = temp_val;
  }
  
  return p - data;
}

static void update_rtt_estimate(clock_time_t rtt_sample) {
  if(client.min_rtt == 0 || rtt_sample < client.min_rtt) {
    client.min_rtt = rtt_sample;
  }
  
  client.latest_rtt = rtt_sample;
  
  if(client.smoothed_rtt == 0) {
    client.smoothed_rtt = rtt_sample;
    client.rtt_variance = rtt_sample / 2;
  } else {
    clock_time_t delta = client.smoothed_rtt - rtt_sample;
    client.rtt_variance = (3 * client.rtt_variance + ABS(delta)) / 4;
    client.smoothed_rtt = (7 * client.smoothed_rtt + rtt_sample) / 8;
  }
  
  LOG_DBG("RTT Update: latest=%u, smoothed=%u, min=%u\n",
          (unsigned)client.latest_rtt, 
          (unsigned)client.smoothed_rtt, 
          (unsigned)client.min_rtt);
}

static void handle_ack_frame(quic_ack_frame_t *ack) {
  /* Détection ACKs dupliqués */
  if(ack->largest_acked == client.largest_acked_packet) {
    cc_on_dup_ack(ack->largest_acked);
  } else {
    client.dup_ack_count = 0;
    client.largest_acked_packet = ack->largest_acked;
  }

  uint32_t bytes_acked = 0;
  for(int i = 0; i < ack->num_ack_ranges; i++) {
    if(ack->ack_ranges[i] == client.pending_packets[client.packet_head].packet_number) {
      clock_time_t rtt = clock_time() - client.pending_packets[client.packet_head].send_time;
      update_rtt_estimate(rtt);
      ctimer_stop(&client.pending_packets[client.packet_head].timer);
      bytes_acked += ack->ack_ranges[i];
      client.packet_head = (client.packet_head + 1) % 4;
    }
  }
  
  cc_on_ack(ack->largest_acked, bytes_acked);
  
  if(ack->ack_delay > client.smoothed_rtt * 2) {
    client.flow_control_window = MAX(INITIAL_WINDOW_SIZE, 
                                   client.flow_control_window / 2);
  } else {
    client.flow_control_window = MIN(client.flow_control_window + 1024, 
                                   INITIAL_WINDOW_SIZE * 4);
  }
}

/* Packet Management */
static void retry_packet(void *ptr) {
  quic_packet_t *pkt = (quic_packet_t *)ptr;
  
  if(client.retry_count < MAX_RETRIES && client.state < QUIC_STATE_CLOSING) {
    client.retry_count++;
    LOG_INFO("Retry #%d for packet %"PRIu32"\n", client.retry_count, pkt->packet_number);
    simple_udp_send(&client.udp_conn, pkt->data, pkt->len);
    ctimer_restart(&pkt->timer);
  } else {
    cc_on_loss(pkt->packet_number);
    LOG_ERR("Max retries reached for packet %"PRIu32"\n", pkt->packet_number);
    client.state = QUIC_STATE_CLOSING;
  }
}

static void queue_packet_for_retransmission(uint8_t *data, uint16_t len, uint32_t pn) {
  if((client.packet_tail + 1) % 4 == client.packet_head) {
    LOG_WARN("Retransmit queue full, dropping packet %"PRIu32"\n", pn);
    return;
  }
  
  memcpy(client.pending_packets[client.packet_tail].data, data, len);
  client.pending_packets[client.packet_tail].len = len;
  client.pending_packets[client.packet_tail].packet_number = pn;
  client.pending_packets[client.packet_tail].send_time = clock_time();
  
  ctimer_set(&client.pending_packets[client.packet_tail].timer, 
             MAX(RETRY_TIMEOUT, client.smoothed_rtt * 2),
             retry_packet, &client.pending_packets[client.packet_tail]);
  
  client.packet_tail = (client.packet_tail + 1) % 4;
  client.total_packets_sent++;
  client.total_bytes_sent += len;
}

/* Stream Management */
static void close_stream(quic_stream_t *stream) {
  if(stream && stream->in_use) {
    ctimer_stop(&stream->timeout_timer);
    stream->state = STREAM_CLOSED;
    stream->in_use = 0;
    LOG_DBG("Stream %d closed\n", stream->stream_id);
  }
}

static void stream_timeout_handler(void *stream_ptr) {
  quic_stream_t *stream = (quic_stream_t *)stream_ptr;
  LOG_WARN("Stream %d timeout - closing\n", stream->stream_id);
  close_stream(stream);
}

static quic_stream_t *open_stream(uint16_t stream_id) {
  for(int i = 0; i < MAX_STREAMS; i++) {
    if(!client.streams[i].in_use) {
      client.streams[i].stream_id = stream_id;
      client.streams[i].state = STREAM_OPEN;
      client.streams[i].read_offset = 0;
      client.streams[i].write_offset = 0;
      client.streams[i].max_data = INITIAL_WINDOW_SIZE;
      client.streams[i].in_use = 1;
      ctimer_set(&client.streams[i].timeout_timer, STREAM_TIMEOUT, 
                stream_timeout_handler, &client.streams[i]);
      return &client.streams[i];
    }
  }
  
  for(int i = 0; i < MAX_STREAMS; i++) {
    if(client.streams[i].state == STREAM_HALF_CLOSED_REMOTE) {
      close_stream(&client.streams[i]);
      client.streams[i].stream_id = stream_id;
      client.streams[i].state = STREAM_OPEN;
      client.streams[i].read_offset = 0;
      client.streams[i].write_offset = 0;
      client.streams[i].max_data = INITIAL_WINDOW_SIZE;
      client.streams[i].in_use = 1;
      ctimer_set(&client.streams[i].timeout_timer, STREAM_TIMEOUT, 
                stream_timeout_handler, &client.streams[i]);
      return &client.streams[i];
    }
  }
  
  LOG_WARN("No available streams, recycling stream IDs\n");
  client.current_stream_cycle++;
  return NULL;
}

static void reset_packet_counter(void *ptr) {
  LOG_INFO("Packet Counters Reset - Sent: %"PRIu32", Received: %"PRIu32", Bytes Sent: %"PRIu32", Bytes Received: %"PRIu32"\n",
          client.total_packets_sent, client.total_packets_received,
          client.total_bytes_sent, client.total_bytes_received);
          
  client.total_packets_sent = 0;
  client.total_packets_received = 0;
  client.total_bytes_sent = 0;
  client.total_bytes_received = 0;
  
  etimer_reset(&client.packet_counter_timer);
}

/* Connection Management */
static int send_to_peer(dtls_context_t *ctx, dtls_session_t *session, 
                       uint8_t *data, size_t len) {
  if(client.bytes_in_flight + len > client.cwnd) {
    LOG_DBG("CC: Window full (in_flight=%"PRIu32", cwnd=%"PRIu32")\n",
           client.bytes_in_flight, client.cwnd);
    return -1;
  }

  quic_header_t hdr = {
    .packet_type = (client.state == QUIC_STATE_HANDSHAKE) ? PACKET_TYPE_HANDSHAKE : PACKET_TYPE_1RTT,
    .connection_id = client.connection_id,
    .packet_number = client.next_packet_number,
    .stream_id = 0
  };
  
  uint8_t pkt_len = encode_quic_packet(&hdr, data, len, buffer);
  
  if(client.state == QUIC_STATE_HANDSHAKE) {
    queue_packet_for_retransmission(buffer, pkt_len, client.next_packet_number);
  }
  
  simple_udp_send(&client.udp_conn, buffer, pkt_len);
  client.next_packet_number++;
  client.total_packets_sent++;
  client.total_bytes_sent += pkt_len;
  cc_on_packet_sent(hdr.packet_number, pkt_len);
  
  LOG_DBG("Sent DTLS message (%"PRIu16" bytes), PN: %"PRIu32"\n", (uint16_t)len, hdr.packet_number);
  return len;
}

static int read_from_peer(dtls_context_t *ctx, dtls_session_t *session,
                         uint8_t *data, size_t len) {
  LOG_INFO("Received DTLS message (%"PRIu16" bytes): %.*s\n", (uint16_t)len, (int)len, data);
  
  client.total_packets_received++;
  client.total_bytes_received += len;
  
  if(!client.handshake_complete) {
    client.handshake_complete = 1;
    client.state = QUIC_STATE_ACTIVE;
    LOG_INFO("DTLS handshake completed\n");
    
    while(client.packet_head != client.packet_tail) {
      ctimer_stop(&client.pending_packets[client.packet_head].timer);
      client.packet_head = (client.packet_head + 1) % 4;
    }
    
    client.retry_count = 0;
    etimer_set(&client.data_timer, client.smoothed_rtt * 3);
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

static void start_dtls_handshake() {
  client.dtls_ctx = dtls_new_context();
  if(!client.dtls_ctx) {
    LOG_ERR("Failed to create DTLS context\n");
    return;
  }

  client.dtls_ctx->app_data = &client.state;
  client.dtls_ctx->handler.write = send_to_peer;
  client.dtls_ctx->handler.read = read_from_peer;
  client.dtls_ctx->handler.get_psk_info = get_psk_info;

  client.dtls_session.size = sizeof(uip_ipaddr_t);
  client.dtls_session.port = UIP_HTONS(SERVER_PORT);
  uip_ip6addr(&client.dtls_session.addr, 0xfe80, 0, 0, 0, 0x0202, 0x0002, 0x0002, 0x0002);

  if(dtls_connect(client.dtls_ctx, &client.dtls_session) < 0) {
    LOG_ERR("DTLS connect failed\n");
  } else {
    client.state = QUIC_STATE_HANDSHAKE;
    LOG_INFO("DTLS handshake initiated\n");
  }
}

static void send_initial_handshake() {
  quic_header_t hdr = {
    .packet_type = PACKET_TYPE_INITIAL,
    .connection_id = client.connection_id,
    .packet_number = client.next_packet_number,
    .stream_id = 0
  };
  
  uint8_t payload[] = "QUIC Initial Handshake";
  uint8_t len = encode_quic_packet(&hdr, payload, sizeof(payload), buffer);
  
  queue_packet_for_retransmission(buffer, len, client.next_packet_number);
  simple_udp_send(&client.udp_conn, buffer, len);
  client.next_packet_number++;
  client.total_packets_sent++;
  client.total_bytes_sent += len;
  cc_on_packet_sent(hdr.packet_number, len);
  
  LOG_INFO("Initial handshake packet sent (PN: %"PRIu32")\n", hdr.packet_number);
}

static void send_application_data() {
  if(client.state != QUIC_STATE_ACTIVE) {
    LOG_WARN("Cannot send data, connection not active\n");
    return;
  }
  
  static uint8_t next_stream = 1;
  quic_stream_t *stream = open_stream(next_stream);
  if(!stream) {
    next_stream = 1;
    stream = open_stream(next_stream);
    if(!stream) {
      LOG_ERR("Failed to open any stream\n");
      return;
    }
  }
  
  next_stream = (next_stream % MAX_STREAMS) + 1;
  
  quic_header_t hdr = {
    .packet_type = PACKET_TYPE_1RTT,
    .connection_id = client.connection_id,
    .packet_number = client.next_packet_number,
    .stream_id = stream->stream_id
  };

  static uint8_t counter = 0;
  char payload[40];
  snprintf(payload, sizeof(payload), "Data on stream %d, packet %d, cycle %"PRIu32, 
           stream->stream_id, ++counter, client.current_stream_cycle);
  
  uint8_t len = encode_quic_packet(&hdr, (uint8_t *)payload, strlen(payload)+1, buffer);
  print_energy_consumption();
  
  if(stream->write_offset + strlen(payload) > stream->max_data) {
    LOG_WARN("Stream %d flow control exceeded\n", stream->stream_id);
    return;
  }
  
  if(client.bytes_in_flight + len > client.cwnd) {
    LOG_DBG("CC: Window full, delaying stream %d data\n", stream->stream_id);
    return;
  }
  
  simple_udp_send(&client.udp_conn, buffer, len);
  stream->write_offset += strlen(payload);
  client.next_packet_number++;
  client.total_packets_sent++;
  client.total_bytes_sent += len;
  cc_on_packet_sent(hdr.packet_number, len);
  
  stream->state = STREAM_HALF_CLOSED_LOCAL;
  ctimer_reset(&stream->timeout_timer);
  
  LOG_INFO("Sent data on stream %d (PN: %"PRIu32", Offset: %"PRIu32"): %s\n", 
          stream->stream_id, hdr.packet_number, stream->write_offset, payload);
}

static void initiate_graceful_close() {
  if(client.state == QUIC_STATE_CLOSING || 
     client.state == QUIC_STATE_CLOSED) return;
  
  client.state = QUIC_STATE_CLOSING;
  
  for(int i = 0; i < MAX_STREAMS; i++) {
    close_stream(&client.streams[i]);
  }
  
  quic_header_t hdr = {
    .packet_type = PACKET_TYPE_1RTT,
    .connection_id = client.connection_id,
    .packet_number = client.next_packet_number++,
    .stream_id = 0
  };
  
  const char *close_msg = "CONNECTION_CLOSE";
  uint8_t len = encode_quic_packet(&hdr, (uint8_t *)close_msg, strlen(close_msg)+1, buffer);
  simple_udp_send(&client.udp_conn, buffer, len);
  client.total_packets_sent++;
  client.total_bytes_sent += len;
  cc_on_packet_sent(hdr.packet_number, len);

  LOG_INFO("Initiated graceful closure\n");
  etimer_set(&client.retry_timer, client.smoothed_rtt * 2);
}

/* UDP Packet Handler */
static void udp_handler(struct simple_udp_connection *c,
                       const uip_ipaddr_t *sender_addr,
                       uint16_t sender_port,
                       const uip_ipaddr_t *receiver_addr,
                       uint16_t receiver_port,
                       const uint8_t *data,
                       uint16_t datalen) {
  LOG_DBG("Received %"PRIu16" bytes from [", datalen);
  LOG_DBG_6ADDR(sender_addr);
  LOG_DBG_("]:%"PRIu16"\n", sender_port);
  
  client.total_packets_received++;
  client.total_bytes_received += datalen;
  
  quic_header_t hdr;
  if(decode_quic_packet((uint8_t *)data, datalen, &hdr) > 0) {
    LOG_DBG("Packet type: %d, CID: %02x, PN: %"PRIu32", Stream: %d\n", 
            hdr.packet_type, hdr.connection_id, hdr.packet_number, hdr.stream_id);
    
    if(hdr.packet_number > client.largest_received_packet) {
      client.largest_received_packet = hdr.packet_number;
    }
    
    if(hdr.packet_type == PACKET_TYPE_HANDSHAKE || 
       hdr.packet_type == PACKET_TYPE_1RTT) {
      dtls_handle_message(client.dtls_ctx, &client.dtls_session, 
                         (uint8_t *)(data + QUIC_HEADER_LEN), datalen - QUIC_HEADER_LEN);
      
      if(hdr.stream_id > 0) {
        for(int i = 0; i < MAX_STREAMS; i++) {
          if(client.streams[i].stream_id == hdr.stream_id) {
            if(client.streams[i].state == STREAM_OPEN) {
              client.streams[i].state = STREAM_HALF_CLOSED_REMOTE;
              ctimer_reset(&client.streams[i].timeout_timer);
            }
            break;
          }
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
    else {
      LOG_WARN("Unknown packet type %d\n", hdr.packet_type);
    }
  }
}

/* Main Process */
PROCESS(quic_client_process, "QUIC Client");
AUTOSTART_PROCESSES(&quic_client_process);

PROCESS_THREAD(quic_client_process, ev, data) {
  static struct etimer init_timer;

  PROCESS_BEGIN();

  energest_init();
  PROCESS_PAUSE();

  memset(&client, 0, sizeof(client));
  client.state = QUIC_STATE_INIT;
  client.flow_control_window = INITIAL_WINDOW_SIZE;
  client.connection_id = INITIAL_CID;
  client.current_stream_cycle = 0;
  
  for(int i = 0; i < MAX_STREAMS; i++) {
    client.streams[i].state = STREAM_CLOSED;
    client.streams[i].in_use = 0;
  }
  
  cc_init();
  
  uip_ipaddr_t server_addr;
  uip_ip6addr(&server_addr, 0xfe80, 0, 0, 0, 0x0202, 0x0002, 0x0002, 0x0002);
  simple_udp_register(&client.udp_conn, CLIENT_PORT, &server_addr, SERVER_PORT, udp_handler);
  
  LOG_INFO("Enhanced QUIC Client started:\n");
  LOG_INFO("- Local port: %"PRIu16"\n", CLIENT_PORT);
  LOG_INFO("- Server port: %"PRIu16"\n", SERVER_PORT);
  LOG_INFO_6ADDR(&server_addr);
  LOG_INFO_("\n");

  etimer_set(&init_timer, CLOCK_SECOND * 2);
  etimer_set(&client.energest_timer, ENERGETIC_REPORT_INTERVAL);
  etimer_set(&client.packet_counter_timer, PACKET_COUNTER_RESET_INTERVAL);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&init_timer));

  start_dtls_handshake();
  send_initial_handshake();
  
  etimer_set(&client.retry_timer, CONNECTION_TIMEOUT);
  etimer_set(&client.data_timer, CLOCK_SECOND * 5);

  while(1) {
    PROCESS_YIELD();
    
    if(ev == PROCESS_EVENT_TIMER) {
      if(data == &client.data_timer) {
        send_application_data();
        etimer_reset(&client.data_timer);
      }
      else if(data == &client.retry_timer) {
        if(client.state == QUIC_STATE_CLOSING) {
          if(client.dtls_ctx) dtls_free_context(client.dtls_ctx);
          LOG_INFO("Connection closed\n");
          PROCESS_EXIT();
        } else {
          LOG_WARN("Connection timeout\n");
          initiate_graceful_close();
        }
      }
      else if(data == &client.packet_counter_timer) {
        reset_packet_counter(NULL);
      }
    }
  }

  PROCESS_END();
}
