package argente

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"

	"golang.org/x/crypto/hkdf"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/pnet"
	"github.com/libp2p/go-libp2p-core/transport"

	p2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"

	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"

	logme "github.com/gologme/log"
	logging "github.com/ipfs/go-log/v2"

	ma "github.com/multiformats/go-multiaddr"
	mafmt "github.com/multiformats/go-multiaddr-fmt"

	"github.com/lucas-clemente/quic-go"
)

var log = logging.Logger("pin-argenté-tpt")

const statelessResetKeyInfo = "libp2p Pin argenté stateless reset key"
const P_PIN_ARGENTÉ = 0x3f42

func init() {
	ma.AddProtocol(ma.Protocol{
		Name:  "pin-argenté",
		Code:  P_PIN_ARGENTÉ,
		VCode: binary.AppendUvarint(nil, P_PIN_ARGENTÉ),
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
	network   core.Core
	priv      crypto.PrivKey
	id        peer.ID
	rcmgr     network.ResourceManager
	tlsId     *p2ptls.Identity
	qConfig   *quic.Config
	listening uint32
}

var ErrOnlySupportEd25519 = errors.New("Pin argenté only supports Ed25519 keys")
var ErrPrivateNetworkNotSupported = errors.New("Pin argenté doesn't support private networks")

var quicConfig = &quic.Config{
	MaxIncomingStreams:         256,
	MaxIncomingUniStreams:      -1,             // disable unidirectional streams
	MaxStreamReceiveWindow:     10 * (1 << 20), // 10 MB
	MaxConnectionReceiveWindow: 15 * (1 << 20), // 15 MB
	AcceptToken: func(clientAddr net.Addr, _ *quic.Token) bool {
		// TODO(#6): require source address validation when under load
		return true
	},
	KeepAlive: true,
	Versions:  []quic.VersionNumber{quic.VersionDraft29, quic.Version1},
}

func New(peers, listens []string, localDiscovery bool) func(priv crypto.PrivKey, pub crypto.PubKey, id peer.ID, psk pnet.PSK, rcmgr network.ResourceManager) (transport.Transport, error) {
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
		pubBytes, err := pub.Raw()
		if err != nil {
			return nil, err
		}

		tlsId, err := p2ptls.NewIdentity(priv)
		if err != nil {
			return nil, err
		}

		keyReader := hkdf.New(sha256.New, privBytes, nil, []byte(statelessResetKeyInfo))
		qConfig := quicConfig.Clone()
		qConfig.StatelessResetKey = make([]byte, 32)
		_, err = io.ReadFull(keyReader, qConfig.StatelessResetKey)
		if err != nil {
			return nil, err
		}
		qConfig.Tracer = tracer

		if rcmgr == nil {
			rcmgr = network.NullResourceManager
		}

		p := &pinArgenté{
			priv:    priv,
			id:      id,
			rcmgr:   rcmgr,
			tlsId:   tlsId,
			qConfig: qConfig,
		}

		// TODO: refactor logging to be compatible with our logging system
		l := logme.Default()
		l.DisableAllLevels()

		conf := &config.NodeConfig{
			// TODO: refactor yggdrasil-go to accept crypto/ed25519 types, hexing here is silly
			PrivateKey: hex.EncodeToString(privBytes),
			PublicKey:  hex.EncodeToString(pubBytes),
			Peers:      peers,
			Listen:     listens,
			// TODO: test with increasing this limit
			IfMTU: 1500,
			NodeInfo: map[string]interface{}{
				"pin-argenté": true,
			},
		}

		if localDiscovery {
			conf.MulticastInterfaces = []config.MulticastInterfaceConfig{{
				Regex:  "*",
				Beacon: true,
				Listen: true,
				Port:   0,
			}}
		}

		// this double encrypts the traffic, investigate and remove not quic's encryption
		err = p.network.Start(conf, l)
		if err != nil {
			return nil, err
		}

		return p, nil
	}
}

func (p *pinArgenté) Close() error {
	return p.network.Close()
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
