// +build linux

package framework

import (
	"github.com/pkg/errors"
)

/*
#define _GNU_SOURCE
#include <sched.h>
*/
import "C"

var errGetCPUFailed = errors.New("getcpu() failed")

func getCPU() (int, error) {
	r := C.sched_getcpu()
	if r < 0 {
		return 0, errGetCPUFailed
	}
	return int(r), nil
}
