# Pin argenté

Pin argenté is a libp2p transport on working on [Ironwood](https://github.com/Arceliar/ironwood) and [go-QUIC](https://github.com/lucas-clemente/quic-go).

It allows libp2p nodes to efficiently exchange data on the [yggdrasil](https://yggdrasil-network.github.io/) network.

Note, Pin argenté is **NOT** part of the yggdrasil IPv6 overlay network. It can route data with yggdrasil's nodes (in both direction), but yggdrasil nodes can't connect to Pin argenté one.
