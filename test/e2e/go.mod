module github.com/travelping/upg-vpp/test/e2e

go 1.13

replace github.com/wmnsk/go-pfcp => /Users/ivan4th/work/travelping/go-pfcp

require (
	git.fd.io/govpp.git v0.3.5
	github.com/containernetworking/plugins v0.8.7
	github.com/onsi/ginkgo v1.8.0
	github.com/onsi/gomega v1.1.0
	github.com/pkg/errors v0.9.1
	github.com/safchain/ethtool v0.0.0-20200804214954-8f958a28363a
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae
	github.com/wmnsk/go-pfcp v0.0.6
	golang.org/x/sys v0.0.0-20200217220822-9197077df867
)
