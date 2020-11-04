// +build !linux

package network

import (
	"github.com/pkg/errors"
)

func (netns *NetNS) disableOffloading(linkName string) error {
	return errors.New("not implemented")
}

func (netns *NetNS) SetNetem(linkName string, attrs NetemAttrs) error {
	return errors.New("not implemented")
}

func (netns *NetNS) DelNetem(linkName string) (bool, error) {
	return false, errors.New("not implemented")
}
