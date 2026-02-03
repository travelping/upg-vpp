module github.com/travelping/upg-vpp/test/e2e

go 1.24.9

replace go.fd.io/govpp => github.com/travelping/govpp v0.8.0-alpha-tp.1

// TODO: https://github.com/go-ping/ping/pull/116
replace github.com/go-ping/ping => github.com/ivan4th/ping v0.0.0-20201105224649-bfa92e2c3093

replace github.com/vmware/go-ipfix => github.com/ivan4th/go-ipfix v0.2.1-0.20220221212718-b192e67cc721

require (
	github.com/containernetworking/plugins v0.8.7
	github.com/go-ping/ping v0.0.0-20201022122018-3977ed72668a
	github.com/google/gopacket v1.1.19
	github.com/mitchellh/go-ps v1.0.0
	github.com/onsi/ginkgo/v2 v2.27.2
	github.com/onsi/gomega v1.38.2
	github.com/pkg/errors v0.9.1
	github.com/safchain/ethtool v0.6.1
	github.com/shirou/gopsutil/v3 v3.20.12
	github.com/sirupsen/logrus v1.9.3
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	github.com/vishvananda/netlink v1.3.1
	github.com/vishvananda/netns v0.0.5
	github.com/vmware/go-ipfix v0.5.11
	github.com/wmnsk/go-gtp v0.8.12
	github.com/wmnsk/go-pfcp v0.0.24
	go.fd.io/govpp v0.6.0
	golang.org/x/sys v0.39.0
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
)

require (
	github.com/Masterminds/semver/v3 v3.4.0 // indirect
	github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d // indirect
	github.com/containernetworking/cni v0.8.0 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/ftrvxmtrx/fd v0.0.0-20150925145434-c6d800382fff // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/pprof v0.0.0-20251208000136-3d256cb9ff16 // indirect
	github.com/lunixbochs/struc v0.0.0-20241101090106-8d528fa2c543 // indirect
	github.com/nxadm/tail v1.4.11 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/pion/dtls/v2 v2.2.12 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/transport/v2 v2.2.10 // indirect
	github.com/pion/transport/v3 v3.0.7 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/mod v0.31.0 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	golang.org/x/tools v0.40.0 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
)
