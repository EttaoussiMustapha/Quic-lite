#ifndef CONTIKI_DTLS_H
#define CONTIKI_DTLS_H

#include "dtls_session.h"
#include "sys/ctimer.h"
#include "net/ipv6/uip.h"

typedef struct dtls_connection {
  dtls_session_t session;
  struct dtls_connection *next;
} dtls_connection_t;

typedef struct dtls_context_t {
  struct ctimer retransmit_timer;
  dtls_connection_t *connections;
  void *app_data;
  struct {
    int (*write)(struct dtls_context_t *, dtls_session_t *, uint8_t *, size_t);
    int (*read)(struct dtls_context_t *, dtls_session_t *, uint8_t *, size_t);
    int (*get_psk_info)(struct dtls_context_t *, dtls_session_t *,
                       const uint8_t *, size_t, uint8_t *, size_t);
  } handler;
} dtls_context_t;

/* Public API */
dtls_context_t *dtls_new_context(void);
void dtls_free_context(dtls_context_t *ctx);
int dtls_connect(dtls_context_t *ctx, dtls_session_t *session);
int dtls_write(dtls_context_t *ctx, dtls_session_t *session,
              uint8_t *data, size_t len);
void dtls_handle_message(dtls_context_t *ctx, dtls_session_t *session,
                        uint8_t *data, size_t len);

#endif /* CONTIKI_DTLS_H */
