#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Network Configuration */
#define UIP_CONF_IPV6 1
#define UIP_CONF_ICMP6 1

/* Buffer Sizes */
#define UIP_CONF_BUFFER_SIZE 256
#define UIP_CONF_RECEIVE_WINDOW 256

/* QUIC Configuration */
#define QUIC_SERVER_PORT 5688
#define QUIC_CLIENT_PORT 8765
#define QUIC_CONNECTION_TIMEOUT 60  /* seconds */
#define QUIC_RETRY_TIMEOUT 2        /* seconds */
#define QUIC_MAX_CONNECTIONS 5
#define QUIC_BUFFER_SIZE 1280       /* bytes */

/* DTLS Configuration */
#define DTLS_MAX_BUF 256
#define DTLS_PEER_MAX 1
#define DTLS_HANDSHAKE_MAX 1

/* Logging */
#define LOG_CONF_LEVEL_QUIC LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_DTLS LOG_LEVEL_WARN

#endif /* PROJECT_CONF_H_ */
