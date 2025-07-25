#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Network Configuration */
#define UIP_CONF_IPV6 1
#define UIP_CONF_ICMP6 1

/* Port Definitions */
#define QUIC_SERVER_PORT 5688
#define QUIC_CLIENT_PORT 8765

/* Buffer Sizes */
#define UIP_CONF_BUFFER_SIZE 256
#define UIP_CONF_RECEIVE_WINDOW 256

/* QUIC Timeouts (in seconds) */
#define QUIC_IDLE_TIMEOUT 60         // For server-side cleanup
#define QUIC_CONNECTION_TIMEOUT 30   // For client-side connection attempts
#define QUIC_RETRY_TIMEOUT 2         // Between retransmissions

/* QUIC Limits */
#define QUIC_MAX_CONNECTIONS 5
#define QUIC_HEADER_LEN 8
#define QUIC_BUFFER_SIZE 1280

/* DTLS Configuration */
#define DTLS_MAX_BUF 256
#define DTLS_PEER_MAX 1
#define DTLS_HANDSHAKE_MAX 1

/* Logging */
#define LOG_CONF_LEVEL_QUIC LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_DTLS LOG_LEVEL_WARN
#define ENERGEST_CONF_ON 1

#endif /* PROJECT_CONF_H_ */
