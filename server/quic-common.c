#include "quic-lite.h"
#include "packet-format.h"
#include "lib/random.h"
#include <stdio.h>
#include <string.h>

#define MAX_OUTSTANDING_PACKETS 10
#define RETRANSMIT_TIMEOUT (CLOCK_SECOND * 2)

struct outstanding_packet {
  uint16_t packet_num;
  clock_time_t sent_time;
  uint8_t retransmit_count;
  uint8_t data[UIP_BUFSIZE - sizeof(quic_header_t)];
  uint16_t data_len;
};

static struct outstanding_packet out_packets[MAX_OUTSTANDING_PACKETS];
static uint16_t next_packet_num = 1;

/* Helper functions */
static int get_free_out_slot() {
  for(int i = 0; i < MAX_OUTSTANDING_PACKETS; i++) {
    if(out_packets[i].packet_num == 0) return i;
  }
  return -1;
}

/* Public functions */
int perform_handshake(struct udp_socket *sock, const uip_ipaddr_t *peer) {
  uint8_t buffer[sizeof(quic_header_t) + sizeof(quic_handshake_t)];
  quic_header_t *hdr = (quic_header_t *)buffer;
  quic_handshake_t *hs = (quic_handshake_t *)hdr->payload;
  
  hdr->type = QUIC_HANDSHAKE;
  hdr->stream_id = 0;
  hdr->packet_num = next_packet_num++;
  hdr->length = sizeof(quic_handshake_t);
  
  hs->version = 1;
  hs->cipher_suite = 1;
  hs->nonce = random_rand();
  
  int slot = get_free_out_slot();
  if(slot >= 0) {
    out_packets[slot].packet_num = hdr->packet_num;
    out_packets[slot].sent_time = clock_time();
    out_packets[slot].retransmit_count = 0;
    memcpy(out_packets[slot].data, buffer, sizeof(buffer));
    out_packets[slot].data_len = sizeof(buffer);
  }
  
  udp_socket_sendto(sock, buffer, sizeof(buffer), peer, UIP_HTONS(3001));
  return 1;
}

void quic_recv_callback(struct udp_socket *s, void *ptr,
                       const uip_ipaddr_t *sender_addr,
                       uint16_t sender_port,
                       const uip_ipaddr_t *receiver_addr,
                       uint16_t receiver_port,
                       const uint8_t *data,
                       uint16_t datalen) {
  if(datalen < sizeof(quic_header_t)) return;
  
  quic_header_t *hdr = (quic_header_t *)data;
  
  switch(hdr->type) {
    case QUIC_ACK: {
      quic_ack_t *ack = (quic_ack_t *)hdr->payload;
      if(ack->nack_packet_num != 0) {
        printf("Received NACK for packet %u\n", ack->nack_packet_num);
      } else {
        printf("Received ACK for packet %u\n", ack->ack_packet_num);
      }
      break;
    }
    case QUIC_STREAM: {
      printf("Received stream data on stream %u: %.*s\n",
             hdr->stream_id, hdr->length, hdr->payload);
      
      // Prepare ACK
      uint8_t ack_buf[sizeof(quic_header_t) + sizeof(quic_ack_t)];
      quic_header_t *ack_hdr = (quic_header_t *)ack_buf;
      quic_ack_t *ack = (quic_ack_t *)ack_hdr->payload;
      
      ack_hdr->type = QUIC_ACK;
      ack_hdr->stream_id = hdr->stream_id;
      ack_hdr->packet_num = next_packet_num++;
      ack_hdr->length = sizeof(quic_ack_t);
      
      ack->ack_packet_num = hdr->packet_num;
      ack->nack_packet_num = 0;
      
      udp_socket_sendto(s, ack_buf, sizeof(ack_buf), sender_addr, sender_port);
      break;
    }
    case QUIC_HANDSHAKE:
      printf("Handshake completed\n");
      break;
    default:
      printf("Received unknown packet type: %u\n", hdr->type);
  }
}
