CONTIKI_PROJECT = quic-server
all: $(CONTIKI_PROJECT)

PROJECT_SOURCEFILES += quic-server.c quic-lite.c contiki-dtls.c

MODULES += os/net/ipv6 os/net/ip os/net
MODULES += os/services/shell
MODULES += os/net/ipv6/multicast
MODULES += os/net/ipv6/udp-socket
MODULES += os/net/ipv6/simple-udp
MODULES += os/net/ipv6/tcpip


CONTIKI = ../../..
include $(CONTIKI)/Makefile.include
