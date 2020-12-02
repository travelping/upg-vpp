// +build linux

package traffic

import (
	"net"

	"github.com/pkg/errors"

	"golang.org/x/sys/unix"
)

func noMTUDiscovery(uc *net.UDPConn) (*net.UDPConn, error) {
	f, err := uc.File()
	if err != nil {
		return nil, errors.Wrap(err, "failed to retrieve file from the conn")
	}
	defer f.Close()

	if err := unix.SetsockoptInt(int(f.Fd()), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT); err != nil {
		return nil, errors.Wrap(err, "setsockopt")
	}

	fc, err := net.FileConn(f)
	if err != nil {
		return nil, errors.Wrap(err, "FileConn")
	}
	return fc.(*net.UDPConn), nil
}
