#include "contiki-dtls.h"
#include "lib/memb.h"
#include "sys/log.h"
#include "sys/ctimer.h"

#define LOG_MODULE "DTLS"
#define LOG_LEVEL LOG_LEVEL_INFO

MEMB(conn_pool, dtls_connection_t, QUIC_MAX_CONNECTIONS);

dtls_context_t *dtls_new_context(void) {
  dtls_context_t *ctx = (dtls_context_t *)malloc(sizeof(dtls_context_t));
  if(ctx) {
    ctx->connections = NULL;
    ctx->app_data = NULL;
    memset(&ctx->handler, 0, sizeof(ctx->handler));
    ctimer_set(&ctx->retransmit_timer, 0, NULL, NULL);
  }
  return ctx;
}

void dtls_free_context(dtls_context_t *ctx) {
  if(ctx) {
    while(ctx->connections) {
      dtls_connection_t *next = ctx->connections->next;
      memb_free(&conn_pool, ctx->connections);
      ctx->connections = next;
    }
    ctimer_stop(&ctx->retransmit_timer);
    free(ctx);
  }
}

int dtls_connect(dtls_context_t *ctx, dtls_session_t *session) {
  dtls_connection_t *conn = memb_alloc(&conn_pool);
  if(!conn) {
    LOG_WARN("No memory for new DTLS connection\n");
    return -1;
  }
  
  memcpy(&conn->session, session, sizeof(dtls_session_t));
  conn->next = ctx->connections;
  ctx->connections = conn;
  
  LOG_INFO("New DTLS connection to [");
  LOG_INFO_6ADDR(&session->addr);
  LOG_INFO_("]:%u\n", session->port);
  return 0;
}

int dtls_write(dtls_context_t *ctx, dtls_session_t *session,
              uint8_t *data, size_t len) {
  if(ctx && ctx->handler.write) {
    return ctx->handler.write(ctx, session, data, len);
  }
  return -1;
}

void dtls_handle_message(dtls_context_t *ctx, dtls_session_t *session,
                        uint8_t *data, size_t len) {
  if(ctx && ctx->handler.read) {
    ctx->handler.read(ctx, session, data, len);
  }
}
