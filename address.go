package argente

import (
	"crypto/ed25519"
	"net"

	"github.com/Arceliar/ironwood/types"
	yaddress "github.com/yggdrasil-network/yggdrasil-go/src/address"
)

var _ net.Addr = address(nil)
var _ types.ConvertibleAddr = address(nil)

// addr is a type made to get arround SNI parsing
type address ed25519.PublicKey

func (a address) Network() string {
	return "Pin-argenté"
}

func (a address) String() string {
	return "[" + net.IP(yaddress.AddrForKey(ed25519.PublicKey(a))[:]).String() + "]:1"
}

func (a address) IronwoodAddr() types.Addr {
	return types.Addr(a)
}
