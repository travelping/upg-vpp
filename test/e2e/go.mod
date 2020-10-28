module github.com/travelping/upg-vpp/test/e2e

go 1.13

replace git.fd.io/govpp.git => /Users/ivan4th/work/travelping/govpp.git

replace github.com/wmnsk/go-pfcp => github.com/ivan4th/go-pfcp v0.0.7-0.20201007115118-38811fc30094

require (
	git.fd.io/govpp.git v0.3.5
	github.com/containernetworking/plugins v0.8.7
	github.com/google/gopacket v1.1.18
	github.com/onsi/ginkgo v1.14.2
	github.com/onsi/gomega v1.10.3
	github.com/pkg/errors v0.9.1
	github.com/safchain/ethtool v0.0.0-20200804214954-8f958a28363a
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae
	github.com/wmnsk/go-pfcp v0.0.6
	golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f
)
