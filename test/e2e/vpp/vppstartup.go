// vppstartup.go - 3GPP TS 29.244 GTP-U UP plug-in
//
// Copyright (c) 2021 Travelping GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vpp

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"text/template"
)

var vppStartupTemplateStr = `
unix {
  nodaemon
  coredump-size unlimited
  full-coredump
  cli-listen {{.CLISock}}
  log {{.VPPLog}}
{{- if .InterruptMode }}
  poll-sleep-usec 100
{{- end }}
}

socksvr {
  socket-name {{.APISock}}
}

api-segment {
  prefix {{.APIPrefix}}
}

api-trace {
  on
}

cpu {
  main-core {{.MainCore}}
{{ if .Multicore }}
  corelist-workers {{.WorkerCore}}
{{ else }}
  workers 0
{{ end }}
}

heapsize 300M

statseg {
  socket-name {{.StatsSock}}
  size 512M
}

plugins {
  path {{.PluginPath}}
  plugin dpdk_plugin.so { disable }
  plugin gtpu_plugin.so { disable }
}

buffers {
  default data-size 10000
}

flowtable {
  log2-size 10
}

{{- if .InterruptMode }}
upf {
  pfcp-server-mode interrupt
}
{{- end }}
`

// vlib {
// 	elog-events 10000000
// 	elog-post-mortem-dump
// }

var startupTemplate *template.Template
var vppIndex int32

// Cores list the logical CPU cores that can be used for VPP.
// It is set in SynchronizedBeforeSuite()
var Cores []int = []int{0, 1}

func init() {
	var err error
	startupTemplate, err = template.New("test").Parse(vppStartupTemplateStr)
	if err != nil {
		panic(err)
	}
}

type VPPStartupConfig struct {
	BinaryPath    string
	PluginPath    string
	CLISock       string
	APISock       string
	StatsSock     string
	VPPLog        string
	APIPrefix     string
	MainCore      int
	WorkerCore    int
	UseGDB        bool
	UseGDBServer  bool
	GDBServerPort int
	Trace         bool
	DispatchTrace bool
	Multicore     bool
	XDP           bool
	InterruptMode bool
}

func (cfg *VPPStartupConfig) SetFromEnv() {
	binPath := os.Getenv("VPP_PATH")
	if binPath != "" {
		cfg.BinaryPath = binPath
	}
	pluginPath := os.Getenv("VPP_PLUGIN_PATH")
	if pluginPath != "" {
		cfg.PluginPath = pluginPath
	}
	cfg.UseGDB = os.Getenv("VPP_NO_GDB") == ""
	cfg.UseGDBServer = cfg.UseGDB && os.Getenv("VPP_GDBSERVER") != ""
	if os.Getenv("VPP_GDB_SERVER_PORT") != "" {
		port, err := strconv.Atoi(os.Getenv("VPP_GDB_SERVER_PORT"))
		if err == nil {
			cfg.GDBServerPort = port
		}
	}
	cfg.Trace = os.Getenv("VPP_TRACE") != ""
	cfg.DispatchTrace = os.Getenv("VPP_DISPATCH_TRACE") != ""
	cfg.Multicore = os.Getenv("VPP_MULTICORE") != ""
	cfg.XDP = os.Getenv("VPP_XDP") != ""
	cfg.InterruptMode = os.Getenv("VPP_INTERRUPT_MODE") != ""
	cfg.SetDefaults()
}

func (cfg *VPPStartupConfig) SetDefaults() {
	if cfg.BinaryPath == "" {
		cfg.BinaryPath = "/usr/bin/vpp"
	}
	if cfg.PluginPath == "" {
		cfg.PluginPath = "/usr/lib/x86_64-linux-gnu/vpp_plugins"
	}
	if cfg.CLISock == "" {
		cfg.CLISock = "/run/vpp/cli.sock"
	}
	if cfg.APISock == "" {
		cfg.APISock = "/run/vpp/api.sock"
	}
	if cfg.StatsSock == "" {
		cfg.StatsSock = "/run/vpp/stats.sock"
	}
	if cfg.VPPLog == "" {
		cfg.VPPLog = "/dev/null"
	}
	if cfg.APIPrefix == "" {
		cfg.APIPrefix = fmt.Sprintf("vpp%d", atomic.AddInt32(&vppIndex, 1))
	}
	if cfg.GDBServerPort == 0 {
		cfg.GDBServerPort = 7777
	}
}

func (cfg VPPStartupConfig) Get() string {
	var b strings.Builder
	if err := startupTemplate.Execute(&b, cfg); err != nil {
		panic(err)
	}
	return b.String()
}

func (cfg VPPStartupConfig) DefaultMTU() int {
	if cfg.XDP {
		// TODO: this is the max MTU value which works for veths.
		// Find out why & whether it's always the case
		// (it may perhaps depend on the kernel version, etc.)
		return 2034
	} else {
		return 9000
	}
}
