package i2p_tpt

import (
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/pnet"
	"github.com/libp2p/go-libp2p/core/transport"

	"github.com/eyedeekay/sam3"

	p2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"

	logging "github.com/ipfs/go-log/v2"

	ma "github.com/multiformats/go-multiaddr"

	"github.com/quic-go/quic-go"
)

var log = logging.Logger("libp2p/i2p-transport")

type i2p struct {
	privP2p   crypto.PrivKey
	id        peer.ID
	rcmgr     network.ResourceManager
	tlsId     *p2ptls.Identity
	datagram  *sam3.DatagramSession
	q         quic.Transport
	sam       *sam3.SAM
	listening atomic.Bool
}

var ErrPrivateNetworkNotSupported = errors.New("i2p transport doesn't support private networks")

const maxQuicPacketBufferSize = 1452

var quicConfig = &quic.Config{
	MaxIncomingStreams:         256,
	MaxIncomingUniStreams:      -1,             // disable unidirectional streams
	MaxStreamReceiveWindow:     10 * (1 << 20), // 10 MB
	MaxConnectionReceiveWindow: 15 * (1 << 20), // 15 MB
}

func New(samAddr string, tunnelOptions []string) func(priv crypto.PrivKey, id peer.ID, psk pnet.PSK, rcmgr network.ResourceManager) (transport.Transport, error) {
	return func(priv crypto.PrivKey, id peer.ID, psk pnet.PSK, rcmgr network.ResourceManager) (transport.Transport, error) {
		if len(psk) > 0 {
			return nil, ErrPrivateNetworkNotSupported
		}

		tlsId, err := p2ptls.NewIdentity(priv)
		if err != nil {
			return nil, err
		}

		if rcmgr == nil {
			rcmgr = &network.NullResourceManager{}
		}

		sam, err := sam3.NewSAM(samAddr)
		if err != nil {
			return nil, err
		}
		var good bool
		defer func() {
			if !good {
				sam.Close()
			}
		}()

		key, err := sam.NewKeys()
		if err != nil {
			return nil, fmt.Errorf("failed to generate i2p keys: %w", err)
		}

		name := "libp2p." + id.String()
		datagram, err := sam.NewDatagramSession(name, key, append([]string{"inbound.nickname=" + name}, tunnelOptions...), 0)
		if err != nil {
			return nil, fmt.Errorf("failed to create i2p datagram session: %w", err)
		}

		p := &i2p{
			privP2p:  priv,
			id:       id,
			rcmgr:    rcmgr,
			tlsId:    tlsId,
			sam:      sam,
			datagram: datagram,
			q:        quic.Transport{Conn: datagram},
		}

		good = true
		return p, nil
	}
}

func (p *i2p) Close() error {
	return errors.Join(p.q.Close(), p.datagram.Close(), p.sam.Close())
}

func (p *i2p) CanDial(addr ma.Multiaddr) bool {
	// FIXME: the address should maybe contain quic-v1 trailer but it's confusing go-libp2p with .Protocols().
	return i2pMaddrMatcher.Matches(addr)
}

var protos = []int{ma.P_GARLIC32, ma.P_GARLIC64}

func (p *i2p) Protocols() []int {
	return protos
}

func (p *i2p) Proxy() bool {
	return false
}

func (p *i2p) String() string {
	return "Pin argenté"
}
