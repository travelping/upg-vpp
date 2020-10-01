// +build !linux

package ns

import (
	"errors"
)

var notImplemented = errors.New("not implemented")

func getCurrentThreadNetNSPath() string {
	panic(notImplemented)
}

func (ns *netNS) Set() error {
	return notImplemented
}

// Creates a new persistent (bind-mounted) network namespace and returns an object
// representing that namespace, without switching to it.
func NewNS() (NetNS, error) {
	return nil, notImplemented
}
