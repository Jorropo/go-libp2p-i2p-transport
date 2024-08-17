# Silverpine

Silverpine is a mestnet libp2p transport compatible with the [Yggdrasil](https://yggdrasil-network.github.io/) mesh network using [Ironwood](https://github.com/Arceliar/ironwood) and [go-QUIC](https://github.com/quic-go/quic-go).

Note, Pin argenté is **NOT** part of the yggdrasil IPv6 overlay network. It can route data with yggdrasil's nodes (in both directions), but yggdrasil nodes can't connect to Pin argenté one since we do some custom crypto and packeting (we use QUIC instead of IPv6).

Note2: right now interop with ygg is broken, Silverpine is missing the YGG meta header.