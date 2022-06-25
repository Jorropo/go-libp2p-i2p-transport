package argente

import (
	mrand "math/rand"
	"reflect"
	"runtime"
	"testing"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/transport"
	rcmgr "github.com/libp2p/go-libp2p-resource-manager"
	ttransport "github.com/libp2p/go-libp2p/p2p/transport/testsuite"

	ma "github.com/multiformats/go-multiaddr"
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

	subTest(t, ta, tb, pinArgentéMaddr, ap)
}

func getFunctionName(i interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}

// subTest is pulled out of ttransport because some tests require multiple listens (which we don't support)
func subTest(t *testing.T, ta, tb transport.Transport, addr ma.Multiaddr, peerA peer.ID) {
	banned := [...]string{
		getFunctionName(ttransport.SubtestStressManyConn10Stream50Msg), // we don't support concurrent listens on a single transport
	}

	for _, f := range ttransport.Subtests {
		fname := getFunctionName(f)
		t.Run(fname, func(t *testing.T) {
			for _, w := range banned {
				if fname == w {
					t.SkipNow()
				}
			}
			f(t, ta, tb, addr, peerA)
		})
	}
}
