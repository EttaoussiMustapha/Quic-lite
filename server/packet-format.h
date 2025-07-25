#ifndef PACKET_FORMAT_H
#define PACKET_FORMAT_H

#include <stdint.h>

#define QUIC_INITIAL      0x00
#define QUIC_HANDSHAKE    0x01
#define QUIC_STREAM       0x02
#define QUIC_ACK          0x03
#define QUIC_NACK         0x04

#pragma pack(push, 1)
typedef struct {
  uint8_t type:2;
  uint8_t stream_id:6;
  uint16_t packet_num;
  uint16_t length;
  uint8_t payload[];
} quic_header_t;

typedef struct {
  uint16_t ack_packet_num;
  uint16_t nack_packet_num;
} quic_ack_t;

typedef struct {
  uint8_t version;
  uint8_t cipher_suite;
  uint32_t nonce;
} quic_handshake_t;
#pragma pack(pop)

#endif
