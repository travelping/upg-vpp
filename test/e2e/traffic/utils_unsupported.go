// +build !linux

package traffic

import (
	"net"

	"github.com/pkg/errors"
)

func noMTUDiscovery(uc *net.UDPConn) (*net.UDPConn, error) {
	return nil, errors.New("not implemented")
}
