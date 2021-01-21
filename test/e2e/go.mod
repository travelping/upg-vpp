module github.com/travelping/upg-vpp/test/e2e

go 1.13

replace github.com/wmnsk/go-pfcp => github.com/ivan4th/go-pfcp v0.0.7-0.20201007115118-38811fc30094

// TODO: https://github.com/go-ping/ping/pull/116
replace github.com/go-ping/ping => github.com/ivan4th/ping v0.0.0-20201105224649-bfa92e2c3093

require (
	git.fd.io/govpp.git v0.3.6-0.20201023094155-cb540dc166c1
	github.com/containernetworking/plugins v0.8.7
	github.com/go-ping/ping v0.0.0-20201022122018-3977ed72668a
	github.com/google/gopacket v1.1.18
	github.com/onsi/ginkgo v1.14.2
	github.com/onsi/gomega v1.10.3
	github.com/pkg/errors v0.9.1
	github.com/prometheus/common v0.14.0 // indirect
	github.com/safchain/ethtool v0.0.0-20200804214954-8f958a28363a
	github.com/shirou/gopsutil v3.20.12+incompatible
	github.com/shirou/gopsutil/v3 v3.20.12
	github.com/sirupsen/logrus v1.6.0
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae
	github.com/wmnsk/go-gtp v0.7.13
	github.com/wmnsk/go-pfcp v0.0.6
	golang.org/x/sys v0.0.0-20201024232916-9f70ab9862d5
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
)
