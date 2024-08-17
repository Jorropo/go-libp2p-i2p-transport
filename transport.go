package argente

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/pnet"
	"github.com/libp2p/go-libp2p-core/transport"

	ironwood "github.com/Arceliar/ironwood/network"

	p2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"

	logging "github.com/ipfs/go-log/v2"

	ma "github.com/multiformats/go-multiaddr"
	mafmt "github.com/multiformats/go-multiaddr-fmt"

	"github.com/quic-go/quic-go"
)

var log = logging.Logger("pin-argenté-tpt")

const statelessResetKeyInfo = "libp2p Pin argenté stateless reset key"
const P_PIN_ARGENTÉ = 0x3f42

func init() {
	VCode := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(VCode, P_PIN_ARGENTÉ)
	VCode = VCode[:n:n]
	ma.AddProtocol(ma.Protocol{
		Name:  "pin-argenté",
		Code:  P_PIN_ARGENTÉ,
		VCode: VCode,
		Size:  0,
	})

	var err error
	pinArgentéMaddr, err = ma.NewComponent("pin-argenté", "")
	if err != nil {
		panic(err)
	}
}

var pinArgentéMaddr ma.Multiaddr

type pinArgenté struct {
	privP2p          crypto.PrivKey
	privStd          ed25519.PrivateKey
	id               peer.ID
	rcmgr            network.ResourceManager
	tlsId            *p2ptls.Identity
	peeringListeners []net.Listener
	packet           *ironwood.PacketConn
	q                quic.Transport
	listening        atomic.Bool
}

var ErrOnlySupportEd25519 = errors.New("Pin argenté only supports Ed25519 keys")
var ErrPrivateNetworkNotSupported = errors.New("Pin argenté doesn't support private networks")

const maxQuicPacketBufferSize = 1452

var quicConfig = &quic.Config{
	MaxIncomingStreams:         256,
	MaxIncomingUniStreams:      -1,             // disable unidirectional streams
	MaxStreamReceiveWindow:     10 * (1 << 20), // 10 MB
	MaxConnectionReceiveWindow: 15 * (1 << 20), // 15 MB
	// TODO; harmonize MTU between QUIC and Ironwood
}

func New(peers, listens []string) func(priv crypto.PrivKey, pub crypto.PubKey, id peer.ID, psk pnet.PSK, rcmgr network.ResourceManager) (transport.Transport, error) {
	return func(priv crypto.PrivKey, pub crypto.PubKey, id peer.ID, psk pnet.PSK, rcmgr network.ResourceManager) (transport.Transport, error) {
		if priv.Type() != crypto.Ed25519 {
			return nil, ErrOnlySupportEd25519
		}

		if len(psk) > 0 {
			return nil, ErrPrivateNetworkNotSupported
		}

		privBytes, err := priv.Raw()
		if err != nil {
			return nil, err
		}
		privEd25519 := ed25519.PrivateKey(privBytes)

		tlsId, err := p2ptls.NewIdentity(priv)
		if err != nil {
			return nil, err
		}

		if rcmgr == nil {
			rcmgr = network.NullResourceManager
		}

		p := &pinArgenté{
			privP2p: priv,
			privStd: privEd25519,
			id:      id,
			rcmgr:   rcmgr,
			tlsId:   tlsId,
		}
		p.packet, err = ironwood.NewPacketConn(privEd25519)
		if err != nil {
			return nil, fmt.Errorf("creating network")
		}
		p.q.Conn = p.packet

		err = p.listenPeerings(listens)
		if err != nil {
			return nil, err
		}

		for _, peer := range peers {
			go func() {
				err := p.dialPeering(peer)
				if err != nil {
					log.Errorf("dialing peering %s: %s", peer, err)
				}
			}()
		}

		return p, nil
	}
}

func (p *pinArgenté) Close() error {
	return errors.Join(p.q.Close(), p.packet.Close(), p.closePeeringListeners())
}

var dialMatcher = mafmt.Base(P_PIN_ARGENTÉ)

func (p *pinArgenté) CanDial(addr ma.Multiaddr) bool {
	return dialMatcher.Matches(addr)
}

var protos = []int{P_PIN_ARGENTÉ}

func (p *pinArgenté) Protocols() []int {
	return protos
}

func (p *pinArgenté) Proxy() bool {
	return false
}

func (p *pinArgenté) String() string {
	return "Pin argenté"
}
