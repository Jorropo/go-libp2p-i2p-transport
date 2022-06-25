package argente

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"net"
	"sync/atomic"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/transport"

	p2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"

	ma "github.com/multiformats/go-multiaddr"

	"github.com/lucas-clemente/quic-go"
)

var ErrAlreadyListening = errors.New("Pin argenté only support listening once at a time")

func (p *pinArgenté) Listen(laddr ma.Multiaddr) (transport.Listener, error) {
	if !p.CanDial(laddr) {
		return nil, ErrNotPinArgentéMaddr
	}

	if atomic.SwapUint32(&p.listening, 1) == 1 {
		return nil, ErrAlreadyListening
	}

	var tlsConf tls.Config
	tlsConf.GetConfigForClient = func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
		// return a tls.Config that verifies the peer's certificate chain.
		// Note that since we have no way of associating an incoming QUIC connection with
		// the peer ID calculated here, we don't actually receive the peer's public key
		// from the key chan.
		conf, _ := p.tlsId.ConfigForPeer("")
		return conf, nil
	}

	qlist, err := quic.Listen(packetConn{&p.network, *(*[ed25519.PublicKeySize]byte)(p.network.PublicKey())}, &tlsConf, p.qConfig)
	if err != nil {
		atomic.StoreUint32(&p.listening, 0)
		return nil, err
	}

	return &listener{
		t:     p,
		qlist: qlist,
	}, nil
}

type listener struct {
	t     *pinArgenté
	qlist quic.Listener
}

func (l *listener) Accept() (transport.CapableConn, error) {
	for {
		qconn, err := l.qlist.Accept(context.Background())
		if err != nil {
			return nil, err
		}
		connScope, err := l.t.rcmgr.OpenConnection(network.DirInbound, false)
		if err != nil {
			qconn.CloseWithError(0, err.Error())
			log.Debugw("resource manager blocked incoming connection", "addr", qconn.RemoteAddr(), "error", err)
			return nil, err
		}
		pub, err := p2ptls.PubKeyFromCertChain(qconn.ConnectionState().TLS.PeerCertificates)
		if err != nil {
			qconn.CloseWithError(0, err.Error())
			connScope.Done()
			return nil, err
		}
		if pub.Type() != crypto.Ed25519 {
			err := ErrOnlySupportEd25519
			qconn.CloseWithError(0, err.Error())
			connScope.Done()
			return nil, err
		}
		id, err := peer.IDFromPublicKey(pub)
		if err != nil {
			qconn.CloseWithError(0, err.Error())
			connScope.Done()
			return nil, err
		}
		if err := connScope.SetPeer(id); err != nil {
			qconn.CloseWithError(0, err.Error())
			log.Debugw("resource manager blocked incoming connection for peer", "peer", id, "addr", qconn.RemoteAddr(), "error", err)
			connScope.Done()
			return nil, err
		}

		return &conn{
			t:     l.t,
			scope: connScope,
			id:    id,
			pub:   pub,
			qconn: qconn,
		}, nil
	}
}

func (l *listener) Multiaddr() ma.Multiaddr {
	return pinArgentéMaddr
}

func (l *listener) Addr() net.Addr {
	return l.t.network.LocalAddr()
}

func (l *listener) Close() error {
	atomic.StoreUint32(&l.t.listening, 0)
	return l.qlist.Close()
}

type packetConn struct {
	net.PacketConn

	pub [ed25519.PublicKeySize]byte
}

func (p packetConn) LocalAddr() net.Addr {
	return address(p.pub[:])
}
