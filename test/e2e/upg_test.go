package exttest

import (
	"flag"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/onsi/ginkgo"
	ginkgoconfig "github.com/onsi/ginkgo/config"
	"github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/travelping/upg-vpp/test/e2e/framework"
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
	ginkgo.RunSpecs(t, "UPG Suite")
}
