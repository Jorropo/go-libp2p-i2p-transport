package i2p_tpt

import (
	"context"
	"errors"
	"fmt"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/transport"

	ma "github.com/multiformats/go-multiaddr"

	"github.com/quic-go/quic-go"
)

var ErrNotPinArgentéMaddr = errors.New("non Pin argenté maddr passed in")

func (p *i2p) Dial(ctx context.Context, rmaddr ma.Multiaddr, id peer.ID) (transport.CapableConn, error) {
	if !p.CanDial(rmaddr) {
		return nil, ErrNotPinArgentéMaddr
	}

	tlsConf, pubc := p.tlsId.ConfigForPeer(id)

	connScope, err := p.rcmgr.OpenConnection(network.DirOutbound, false, rmaddr)
	if err != nil {
		log.Debugw("resource manager blocked outgoing connection", "peer", p, "addr", rmaddr, "error", err)
		return nil, err
	}
	if err := connScope.SetPeer(id); err != nil {
		log.Debugw("resource manager blocked outgoing connection for peer", "peer", p, "addr", rmaddr, "error", err)
		connScope.Done()
		return nil, err
	}

	raddr, err := i2pMaddrToAddr(rmaddr)
	if err != nil {
		connScope.Done()
		return nil, err
	}

	qconn, err := p.q.Dial(ctx, raddr, tlsConf, quicConfig)
	if err != nil {
		connScope.Done()
		return nil, err
	}

	return &conn{
		t:     p,
		scope: connScope,
		id:    id,
		pub:   <-pubc,
		qconn: qconn,
	}, nil
}

type conn struct {
	t     *i2p
	scope network.ConnManagementScope
	id    peer.ID
	pub   crypto.PubKey
	qconn quic.Connection
}

func (c *conn) Transport() transport.Transport {
	return c.t
}

func (c *conn) LocalMultiaddr() ma.Multiaddr {
	addr, err := addrToI2pMaddr(c.qconn.LocalAddr())
	if err != nil {
		panic(fmt.Errorf("unreachable: self address is not valid i2p: %w", err))
	}
	return addr
}

func (c *conn) RemoteMultiaddr() ma.Multiaddr {
	addr, err := addrToI2pMaddr(c.qconn.RemoteAddr())
	if err != nil {
		panic(fmt.Errorf("unreachable: created connection with invalid i2p addr: %w", err))
	}
	return addr
}

func (c *conn) LocalPeer() peer.ID {
	return c.t.id
}

func (c *conn) LocalPrivateKey() crypto.PrivKey {
	return c.t.privP2p
}

func (c *conn) RemotePeer() peer.ID {
	return c.id
}

func (c *conn) RemotePublicKey() crypto.PubKey {
	return c.pub
}

func (c *conn) Scope() network.ConnScope {
	return c.scope
}

func (c *conn) Close() error {
	err := c.qconn.CloseWithError(0, "")
	c.scope.Done()
	return err
}

func (c *conn) IsClosed() bool {
	return c.qconn.Context().Err() != nil
}

func (c *conn) OpenStream(ctx context.Context) (network.MuxedStream, error) {
	qstr, err := c.qconn.OpenStreamSync(ctx)
	return &stream{Stream: qstr}, err
}

func (c *conn) AcceptStream() (network.MuxedStream, error) {
	qstr, err := c.qconn.AcceptStream(context.Background())
	return &stream{Stream: qstr}, err
}

func (c *conn) ConnState() network.ConnectionState {
	return network.ConnectionState{Transport: "i2p"}
}
