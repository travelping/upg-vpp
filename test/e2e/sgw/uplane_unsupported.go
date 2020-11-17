// +build !linux

package sgw

import (
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

const (
	RoleSGSN   = 1
	FAMILY_ALL = unix.AF_UNSPEC
	SCOPE_LINK = 0
)

func (kt *KernelTunnel) UnregisterSession(s Session) error {
	return errors.New("not implemented")
}

func (kt *KernelTunnel) addTunnel(s Session) error {
	return errors.New("not implemented")
}
