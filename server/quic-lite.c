#include "quic-lite.h"
#include <string.h>

uint8_t encode_quic_packet(quic_header_t *hdr, uint8_t *payload, uint16_t payload_len, uint8_t *out_buf) {
    uint8_t *ptr = out_buf;
    
    *ptr++ = hdr->packet_type;
    *ptr++ = hdr->connection_id;
    
    /* Packet number (big-endian) */
    *ptr++ = (hdr->packet_number >> 24) & 0xFF;
    *ptr++ = (hdr->packet_number >> 16) & 0xFF;
    *ptr++ = (hdr->packet_number >> 8) & 0xFF;
    *ptr++ = hdr->packet_number & 0xFF;
    
    /* Stream ID */
    *ptr++ = (hdr->stream_id >> 8) & 0xFF;
    *ptr++ = hdr->stream_id & 0xFF;
    
    /* Payload */
    memcpy(ptr, payload, payload_len);
    ptr += payload_len;
    
    return (ptr - out_buf);
}

uint16_t decode_quic_packet(uint8_t *data, uint16_t len, quic_header_t *hdr) {
    if (len < QUIC_HEADER_LEN) return 0;
    
    uint8_t *ptr = data;
    hdr->packet_type = *ptr++;
    hdr->connection_id = *ptr++;
    
    hdr->packet_number = ((uint32_t)*ptr++ << 24);
    hdr->packet_number |= ((uint32_t)*ptr++ << 16);
    hdr->packet_number |= ((uint32_t)*ptr++ << 8);
    hdr->packet_number |= *ptr++;
    
    hdr->stream_id = ((uint16_t)*ptr++ << 8);
    hdr->stream_id |= *ptr++;
    
    return QUIC_HEADER_LEN;
}
