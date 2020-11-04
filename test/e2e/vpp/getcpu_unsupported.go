// +build !linux

package vpp

import (
	"github.com/pkg/errors"
)

func getCPU() (int, error) {
	return 0, errors.New("not implemented")
}
