package framework

import (
	"testing"
)

func TestVPP(t *testing.T) {
	vi := &VPPInstance{}
	defer vi.TearDown()
	if err := vi.SetupNamespaces(); err != nil {
		t.Fatal(err)
	}
	if err := vi.StartVPP(); err != nil {
		t.Fatal(err)
	}
	if err := vi.Ctl("show version"); err != nil {
		t.Fatal(err)
	}
	if err := vi.ConfigureVPP(); err != nil {
		t.Fatal(err)
	}

	tg := NewTrafficGen(vi.ClientNS, vi.ServerNS)
	defer tg.TearDown()

	if err := tg.SimulateDownloadFromVPPWebServer(); err != nil {
		t.Fatal(err)
	}

	if err := tg.SimulateDownloadThroughProxy(); err != nil {
		t.Fatal(err)
	}
}
