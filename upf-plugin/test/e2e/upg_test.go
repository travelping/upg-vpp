// upg_test.go - 3GPP TS 29.244 GTP-U UP plug-in
//
// Copyright (c) 2021 Travelping GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package exttest

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/sirupsen/logrus"

	"github.com/travelping/upg-vpp/test/e2e/framework"
	"github.com/travelping/upg-vpp/test/e2e/vpp"
)

var pause = flag.Bool("pause", false, "Pause upon failure")
var artifactsDir = flag.String("artifacts-dir", "", "Artifacts directory")

func FailPause(message string, callerSkip ...int) {
	fmt.Fprintf(os.Stderr, "Pausing on error: %s\n", message)
	fmt.Fprintln(os.Stderr, "Press Ctrl-C to stop...")
	for {
		time.Sleep(time.Hour)
	}
}

// Here we select logical CPU cores for parallel Ginkgo nodes starting
// from the least loaded ones.
var _ = ginkgo.SynchronizedBeforeSuite(func() []byte {
	percents, err := cpu.Percent(5*time.Second, true)
	if err != nil {
		log.Panicf("can't get cpu usage: %v", err)
	}
	usage := make([]struct {
		n       uint16
		percent float64
	}, len(percents))
	for n, p := range percents {
		usage[n].n = uint16(n)
		usage[n].percent = p
	}
	sort.Slice(usage, func(i, j int) bool {
		return usage[i].percent < usage[j].percent
	})
	r := make([]byte, len(usage)*2)
	for n, u := range usage {
		binary.LittleEndian.PutUint16(r[n*2:], u.n)
	}
	return r
}, func(data []byte) {
	numCores := len(data) / 2
	var startupCfg vpp.VPPStartupConfig
	startupCfg.SetFromEnv()
	if startupCfg.Multicore {
		// select 2 cores for the current parallel node
		// in the multicore mode
		n := (ginkgo.GinkgoParallelProcess() - 1) % (numCores / 2)
		vpp.Cores = []int{
			int(binary.LittleEndian.Uint16(data[n*4:])),
			int(binary.LittleEndian.Uint16(data[n*4+2:])),
		}
	} else {
		// select a single core for the current parallel node
		// in the single core mode
		n := (ginkgo.GinkgoParallelProcess() - 1) % numCores
		vpp.Cores = []int{
			int(binary.LittleEndian.Uint16(data[n*2:])),
		}
	}
	fmt.Println("Cores:", vpp.Cores)
})

func TestUPG(t *testing.T) {
	if *pause {
		gomega.RegisterFailHandler(FailPause)
	} else {
		gomega.RegisterFailHandler(ginkgo.Fail)
	}
	logrus.SetOutput(ginkgo.GinkgoWriter)
	logrus.SetLevel(logrus.DebugLevel)
	framework.SetArtifactsDirectory(*artifactsDir)
	ginkgo.RunSpecs(t, "UPG Suite")
}
