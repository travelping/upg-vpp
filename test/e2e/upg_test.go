package exttest

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/config"
	ginkgoconfig "github.com/onsi/ginkgo/config"
	"github.com/onsi/ginkgo/reporters"
	"github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/travelping/upg-vpp/test/e2e/framework"
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
