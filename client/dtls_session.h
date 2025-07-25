#ifndef DTLS_SESSION_H
#define DTLS_SESSION_H

#include "net/ipv6/uip.h"

typedef struct {
  uip_ipaddr_t addr;
  uint16_t port;
  unsigned int size;
} dtls_session_t;

#endif /* DTLS_SESSION_H */
