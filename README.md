# QUIC-Lite for Contiki-NG

**QUIC-Lite** is a lightweight, energy-efficient implementation of the QUIC transport protocol designed specifically for constrained IoT devices running the Contiki-NG operating system. It targets low-power motes such as Zolertia Z1 and Tmote Sky, enabling secure, reliable, and multiplexed communication over IEEE 802.15.4 wireless networks.

---

## Project Overview

This project represents one of the first implementations of a QUIC-based transport protocol adapted to IoT-class hardware with extreme resource constraints. The initial development and testing were carried out primarily on the Cooja simulator motes, which provide a controlled environment for energy profiling and network performance evaluation.

QUIC-Lite incorporates a simplified DTLS-style handshake using pre-shared keys (PSK) to establish secure sessions, stream multiplexing for parallel data flows, and lightweight packet retransmission and congestion control algorithms tailored for low-power wireless sensor networks. The protocol is natively integrated with Contiki-NG’s event-driven kernel and leverages the `Energest` module for detailed energy consumption monitoring.

Our aim is to provide a modern, unified transport layer for IoT that bridges the gap between traditional protocols like CoAP or MQTT-SN and full-fledged QUIC stacks unsuitable for constrained devices.

---

## Features

- DTLS-inspired handshake using pre-shared keys for lightweight security
- Stream multiplexing with efficient stream recycling and flow control
- Reliable packet delivery with RTT-based retransmissions
- Congestion control adapted to low-power IEEE 802.15.4 radios
- Energy consumption tracking via Contiki-NG’s `Energest` module
- Native support for IPv6 and RPL routing protocols in Contiki-NG
- Tested extensively on Cooja motes; ongoing work for deployment on Zolertia Z1 and Tmote Sky hardware

---

## Getting Started

### Prerequisites

- [Contiki-NG](https://github.com/contiki-ng/contiki-ng) development environment installed
- Cooja simulator for network emulation
- Basic familiarity with Contiki’s build system and mote simulation

### Build and Run

#### Build the Client

cd examples/quic-lite/client
make TARGET=cooja quic-client

#### Build the server 

cd examples/quic-lite/server
make TARGET=cooja quic-server


## Run in Cooja

- Load the compiled firmware onto respective motes in the Cooja simulator
- Configure simulation parameters (topology, radio model, timing)
- Enable energy logging through Contiki’s Energest for profiling

## Usage Notes

- Simulation parameters such as buffer sizes and retransmission timers can be tuned in `quic-lite.c` to optimize performance or energy usage.
- The protocol currently uses pre-shared keys; future releases may support certificate-based authentication.
- Initial tests and profiling are done in Cooja; work is underway to port to physical motes (Zolertia Z1, Tmote Sky).

## Future Work

- Port QUIC-Lite to physical IoT hardware platforms
- Integrate advanced congestion control algorithms
- Add support for hardware cryptographic accelerators to reduce CPU load
- Explore implementations on other IoT operating systems such as RIOT OS
- Extend protocol features for dynamic network topologies and mobility


## References

- QUIC Protocol Specification, RFC 9000
- Contiki-NG Operating System: https://contiki-ng.org/
- Cooja Simulator: https://github.com/contiki-ng/cooja
