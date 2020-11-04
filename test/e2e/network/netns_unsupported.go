// +build !linux

package network

import (
	"github.com/pkg/errors"
)

func (netns *NetNS) disableOffloading(linkName string) error {
	return errors.New("not implemented")
}
