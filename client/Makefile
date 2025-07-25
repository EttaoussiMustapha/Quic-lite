CONTIKI_PROJECT = quic-client
all: $(CONTIKI_PROJECT)

# Source files
PROJECT_SOURCEFILES += quic-client.c quic-lite.c contiki-dtls.c

# Required modules - CRITICAL CHANGE HERE
MODULES += os/net/ipv6 os/net/ip os/net
MODULES += os/services/shell
MODULES += os/net/ipv6/multicast  # Needed for UDP implementation

CONTIKI = ../../..
include $(CONTIKI)/Makefile.include
