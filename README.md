# I2P Libp2p transport

It allows to use the [I2P network](https://geti2p.net/) as a privacy transport for [libp2p](https://libp2p.io).

This code is experimental and unstable and might have all kinds of bugs. The rest of the stack above such as go-libp2p and applications built on it also need to be reviewed to make sure they do not have IP Leaks.

It uses [SAM3](https://github.com/eyedeekay/sam3/) library to connect to a [local I2P router over the SAM3 protocol](https://geti2p.net/en/docs/api/samv3) which takes care of tunnelling the traffic using garlic routing.

The on wire format is using [I2P datagrams tunnels](https://geti2p.net/en/docs/api/datagrams) with [quic-go](https://github.com/quic-go/quic-go) responsible for implementing libp2p's encryption, reliability, muxing and streams.

Quic-go does it's own end-to-end encryption which is using libp2p TLS extensions, I2P then add it's own end-to-end encryption which is slightly useful to hide the TLS handshake and QUIC pattern.
I2P also then layer encryptions to do garlic routing properly (each hop will remove one encryption layer).