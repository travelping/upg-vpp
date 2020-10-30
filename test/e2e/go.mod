module github.com/travelping/upg-vpp/test/e2e

go 1.13

replace github.com/wmnsk/go-pfcp => github.com/ivan4th/go-pfcp v0.0.7-0.20201007115118-38811fc30094

require (
	git.fd.io/govpp.git v0.3.6-0.20201023094155-cb540dc166c1
	github.com/containernetworking/plugins v0.8.7
	github.com/google/gopacket v1.1.18
	github.com/onsi/ginkgo v1.14.2
	github.com/onsi/gomega v1.10.3
	github.com/pkg/errors v0.9.1
	github.com/prometheus/common v0.14.0 // indirect
	github.com/safchain/ethtool v0.0.0-20200804214954-8f958a28363a
	github.com/sirupsen/logrus v1.6.0
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae
	github.com/wmnsk/go-gtp v0.7.13
	github.com/wmnsk/go-pfcp v0.0.6
	golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f
)