// +build !linux

package framework

import (
	"errors"
	"golang.org/x/sys/unix"
)

const (
	FAMILY_ALL = unix.AF_UNSPEC
	FAMILY_V4  = unix.AF_INET
	FAMILY_V6  = unix.AF_INET6
)

var notImplemented = errors.New("not implemented")

func Sysctl(name string, params ...string) (string, error) {
	return "", notImplemented
}
