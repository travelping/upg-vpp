package exttest

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/config"
	ginkgoconfig "github.com/onsi/ginkgo/config"
	"github.com/onsi/ginkgo/reporters"
	"github.com/onsi/gomega"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/sirupsen/logrus"

	"github.com/travelping/upg-vpp/test/e2e/framework"
	"github.com/travelping/upg-vpp/test/e2e/vpp"
)

var pause = flag.Bool("pause", false, "Pause upon failure")
var artifactsDir = flag.String("artifacts-dir", "", "Artifacts directory")
var junitOutput = flag.String("junit-output", "", "JUnit XML output file")

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
		n := (config.GinkgoConfig.ParallelNode - 1) % (numCores / 2)
		vpp.Cores = []int{
			int(binary.LittleEndian.Uint16(data[n*4:])),
			int(binary.LittleEndian.Uint16(data[n*4+2:])),
		}
	} else {
		// select a single core for the current parallel node
		// in the single core mode
		n := (config.GinkgoConfig.ParallelNode - 1) % numCores
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
	logrus.SetFormatter(&logrus.TextFormatter{
		ForceColors: !ginkgoconfig.DefaultReporterConfig.NoColor,
	})
	framework.SetArtifactsDirectory(*artifactsDir)
	if *junitOutput == "" {
		ginkgo.RunSpecs(t, "UPG Suite")
	} else {
		if err := os.MkdirAll(*junitOutput, os.ModePerm); err != nil {
			t.Fatalf("MkdirAll %q: %v", *junitOutput, err)
		}
		junitXmlFilename := filepath.Join(*junitOutput, fmt.Sprintf("junit_%d.xml", config.GinkgoConfig.ParallelNode))
		junitReporter := reporters.NewJUnitReporter(junitXmlFilename)
		ginkgo.RunSpecsWithDefaultAndCustomReporters(t, "UPG Suite", []ginkgo.Reporter{junitReporter})
	}
}
