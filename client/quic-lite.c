#include "quic-lite.h"
#include <string.h>

uint8_t encode_quic_packet(quic_header_t *hdr, uint8_t *payload, uint16_t payload_len, uint8_t *out_buf) {
    /* Simple packet encoding */
    out_buf[0] = hdr->packet_type;
    out_buf[1] = hdr->connection_id;
    out_buf[2] = (hdr->packet_number >> 24) & 0xFF;
    out_buf[3] = (hdr->packet_number >> 16) & 0xFF;
    out_buf[4] = (hdr->packet_number >> 8) & 0xFF;
    out_buf[5] = hdr->packet_number & 0xFF;
    out_buf[6] = (hdr->stream_id >> 8) & 0xFF;
    out_buf[7] = hdr->stream_id & 0xFF;
    
    if(payload && payload_len > 0) {
        memcpy(out_buf + QUIC_HEADER_LEN, payload, payload_len);
    }
    
    return QUIC_HEADER_LEN + payload_len;
}

uint16_t decode_quic_packet(uint8_t *data, uint16_t len, quic_header_t *hdr) {
    if(len < QUIC_HEADER_LEN) return 0;
    
    hdr->packet_type = data[0];
    hdr->connection_id = data[1];
    hdr->packet_number = (data[2] << 24) | (data[3] << 16) | (data[4] << 8) | data[5];
    hdr->stream_id = (data[6] << 8) | data[7];
    
    return QUIC_HEADER_LEN;
}
