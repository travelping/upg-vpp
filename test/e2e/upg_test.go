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
)

var pause = flag.Bool("pause", false, "Pause upon failure")

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
	ginkgo.RunSpecs(t, "UPG Suite")
}
