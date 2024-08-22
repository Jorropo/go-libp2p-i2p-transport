package i2p_tpt

import (
	"errors"
	"net"
	"strings"

	"github.com/eyedeekay/i2pkeys"

	ma "github.com/multiformats/go-multiaddr"
	mafmt "github.com/multiformats/go-multiaddr-fmt"
)

var emptyMaddr ma.Multiaddr

func init() {
	var err error
	emptyMaddr, err = addrToI2pMaddr(i2pkeys.I2PDestHash{})
	if err != nil {
		panic(err)
	}
}

var errNotI2pNetwork = errors.New("trying to convert non i2p address to i2p multiaddr")

func addrToI2pMaddr(addr net.Addr) (ma.Multiaddr, error) {
	// FIXME: this function does bytes → string → bytes conversion, which is inefficient.
	if destHash, ok := addr.(i2pkeys.I2PDestHash); ok {
		return ma.NewComponent("garlic32", strings.TrimSuffix(destHash.String(), ".b32.i2p"))
	}

	if addr.Network() != "I2P" {
		return nil, errNotI2pNetwork
	}
	saddr := addr.String()
	saddr = strings.TrimSuffix(saddr, ".i2p")
	if strings.HasSuffix(saddr, ".b32") {
		saddr = strings.TrimSuffix(saddr, ".b32")
		return ma.NewMultiaddr("/garlic32/" + saddr)
	}
	return ma.NewMultiaddr("/garlic64/" + saddr)
}

var errNotI2pMaddr = errors.New("trying to convert non i2p multiaddr to i2p address")

var garlic32 = mafmt.Base(ma.P_GARLIC32)
var garlic64 = mafmt.Base(ma.P_GARLIC64)
var i2pMaddrMatcher = mafmt.Or(garlic32, garlic64)

func i2pMaddrToAddr(maddr ma.Multiaddr) (net.Addr, error) {
	// FIXME: this function does bytes → string → bytes conversion, which is inefficient.
	if garlic32.Matches(maddr) {
		str, err := maddr.ValueForProtocol(ma.P_GARLIC32)
		if err != nil {
			return nil, err
		}
		return i2pkeys.DestHashFromString(str + ".b32.i2p")
	}
	if garlic64.Matches(maddr) {
		str, err := maddr.ValueForProtocol(ma.P_GARLIC64)
		if err != nil {
			return nil, err
		}
		return i2pkeys.NewI2PAddrFromString(str)
	}
	return nil, errNotI2pMaddr
}
