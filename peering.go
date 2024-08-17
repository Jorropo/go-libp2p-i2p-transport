package argente

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"
)

func (p *pinArgenté) listenPeerings(addresses []string) (err error) {
	defer func() {
		if err != nil {
			p.closePeeringListeners()
		}
	}()
	for _, addr := range addresses {
		u, err := url.Parse(addr)
		if err != nil {
			return err
		}

		var listener net.Listener
		switch u.Scheme {
		case "tcp":
			listener, err = net.Listen("tcp", u.Host)
		default:
			return fmt.Errorf("unsupported peering transport: %s", u.Scheme)
		}
		if err != nil {
			return err
		}

		p.peeringListeners = append(p.peeringListeners, listener)
		go p.listenPeering(listener)
	}
	return nil
}

func (p *pinArgenté) listenPeering(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}

		go p.handshakeAndAddPeering(conn)
	}
}

func (p *pinArgenté) dialPeering(addr string) error {
	u, err := url.Parse(addr)
	if err != nil {
		return err
	}

	var conn net.Conn
	switch u.Scheme {
	case "tcp":
		conn, err = net.Dial("tcp", u.Host)
	default:
		return fmt.Errorf("unsupported peering transport: %s", u.Scheme)
	}
	if err != nil {
		return err
	}

	return p.handshakeAndAddPeering(conn)
}

const peeringHandshakeTimeout = 15 * time.Second

func (p *pinArgenté) handshakeAndAddPeering(conn net.Conn) (err error) {
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()
	conn.SetDeadline(time.Now().Add(peeringHandshakeTimeout))

	// FIXME: verify the remote's identity
	var sendError error
	var sendSync sync.Mutex
	sendSync.Lock()
	go func() {
		defer sendSync.Unlock()
		_, sendError = conn.Write(p.privStd[len(p.privStd)-ed25519.PublicKeySize:]) // for Ed25519 the public key is trailing the private key
	}()
	remote := make(ed25519.PublicKey, ed25519.PublicKeySize)
	_, err = io.ReadFull(conn, remote)
	if err != nil {
		return err
	}

	sendSync.Lock()
	if sendError != nil {
		return sendError
	}

	return p.packet.HandleConn(remote, conn, 0)
}

func (p *pinArgenté) closePeeringListeners() (err error) {
	for _, l := range p.peeringListeners {
		err = errors.Join(err, l.Close())
	}
	return
}
