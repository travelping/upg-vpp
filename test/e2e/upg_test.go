package exttest

import (
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"testing"
)

func TestUPG(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "UPG Suite")
}
