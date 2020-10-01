package main

import (
	"fmt"
	"log"
	"time"

	"github.com/travelping/upg-vpp/test/e2e/framework"
)

func verify() error {
	vi := &framework.VPPInstance{}
	defer vi.TearDown()
	if err := vi.SetupNamespaces(); err != nil {
		return err
	}
	if err := vi.StartVPP(); err != nil {
		return err
	}
	if err := vi.Ctl("show version"); err != nil {
		return err
	}
	if err := vi.SetupWebserver(); err != nil {
		return err
	}
	// FIXME: rm
	time.Sleep(1 * time.Second)
	if err := vi.SimulateDownload(); err != nil {
		return err
	}

	fmt.Println("*** OK ***")
	return nil
}

func main() {
	if err := verify(); err != nil {
		log.Fatalln(err)
	}
}
