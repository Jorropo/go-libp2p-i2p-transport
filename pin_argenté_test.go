package argente

import (
	mrand "math/rand"
	"testing"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	rcmgr "github.com/libp2p/go-libp2p-resource-manager"
	ttransport "github.com/libp2p/go-libp2p/p2p/transport/testsuite"
)

func TestPinArgentéTransport(t *testing.T) {
	seed := mrand.New(mrand.NewSource(9876543210))
	apriv, apub, err := crypto.GenerateEd25519Key(seed)
	if err != nil {
		t.Fatal(err)
	}
	ap, err := peer.IDFromPublicKey(apub)
	if err != nil {
		t.Fatal(err)
	}

	arcmgr, err := rcmgr.NewResourceManager(rcmgr.NewDefaultLimiter())
	if err != nil {
		t.Fatal(err)
	}

	ta, err := New(nil, []string{"tcp://127.13.37.42:12345"}, false)(apriv, apub, ap, nil, arcmgr)
	if err != nil {
		t.Fatal(err)
	}

	bpriv, bpub, err := crypto.GenerateEd25519Key(seed)
	if err != nil {
		t.Fatal(err)
	}
	bp, err := peer.IDFromPublicKey(bpub)
	if err != nil {
		t.Fatal(err)
	}

	brcmgr, err := rcmgr.NewResourceManager(rcmgr.NewDefaultLimiter())
	if err != nil {
		t.Fatal(err)
	}

	tb, err := New([]string{"tcp://127.13.37.42:12345"}, nil, false)(bpriv, bpub, bp, nil, brcmgr)
	if err != nil {
		t.Fatal(err)
	}

	zero := "/pin-argenté"
	ttransport.SubtestTransport(t, ta, tb, zero, ap)
}
