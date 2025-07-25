#ifndef QUIC_LITE_H
#define QUIC_LITE_H

#include <stdint.h>

/* QUIC Packet Types */
#define PACKET_TYPE_INITIAL    0x00
#define PACKET_TYPE_0RTT       0x01
#define PACKET_TYPE_HANDSHAKE  0x02
#define PACKET_TYPE_1RTT       0x03
#define PACKET_TYPE_RETRY      0x04

/* Header length */
#define QUIC_HEADER_LEN 8  /* packet_type(1) + connection_id(1) + packet_number(4) + stream_id(2) */

typedef struct {
    uint8_t packet_type;
    uint8_t connection_id;
    uint32_t packet_number;
    uint16_t stream_id;
} quic_header_t;

/* Maximum buffer size */
#define MAX_BUFFER_LEN 1280

/* Function prototypes */
uint8_t encode_quic_packet(quic_header_t *hdr, uint8_t *payload, uint16_t payload_len, uint8_t *out_buf);
uint16_t decode_quic_packet(uint8_t *data, uint16_t len, quic_header_t *hdr);

#endif /* QUIC_LITE_H */
