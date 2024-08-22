package i2p_tpt

import (
	"crypto/sha256"
	mrand "math/rand/v2"
	"reflect"
	"runtime"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/transport"
	ttransport "github.com/libp2p/go-libp2p/p2p/transport/testsuite"

	ma "github.com/multiformats/go-multiaddr"
)

func TestI2pTransport(t *testing.T) {
	seed := mrand.NewChaCha8(sha256.Sum256([]byte("i2p-transport-test")))
	apriv, apub, err := crypto.GenerateEd25519Key(seed)
	if err != nil {
		t.Fatal(err)
	}
	ap, err := peer.IDFromPublicKey(apub)
	if err != nil {
		t.Fatal(err)
	}

	opts := []string{"inbound.length=0", "outbound.length=0", "inbound.lengthVariance=0", "outbound.lengthVariance=0", "inbound.quantity=1", "outbound.quantity=1"}

	ta, err := New("127.0.0.1:7656", opts)(apriv, ap, nil, nil)
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

	tb, err := New("127.0.0.1:7656", opts)(bpriv, bp, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	subTest(t, ta, tb, emptyMaddr, ap)
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
