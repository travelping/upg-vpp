package framework

import (
	"os"
	"strings"
	"text/template"
)

var vppStartupTemplateStr = `
unix {
  nodaemon
  log /tmp/vpp.log
  coredump-size unlimited
  full-coredump
  interactive
  cli-listen /run/vpp/cli.sock
}

socksvr {
  socket-name /run/vpp/api.sock
}

api-trace {
  on
}

cpu {
  workers 0
}

statseg {
  size 512M
}

plugins {
  path {{.PluginPath}}
  plugin dpdk_plugin.so { disable }
}

`

// vlib {
// 	elog-events 10000000
// 	elog-post-mortem-dump
// }

var startupTemplate *template.Template

func init() {
	var err error
	startupTemplate, err = template.New("test").Parse(vppStartupTemplateStr)
	if err != nil {
		panic(err)
	}
}

type VPPStartupConfig struct {
	BinaryPath string
	PluginPath string
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
	cfg.SetDefaults()
}

func (cfg *VPPStartupConfig) SetDefaults() {
	if cfg.BinaryPath == "" {
		cfg.BinaryPath = "/usr/bin/vpp"
	}
	if cfg.PluginPath == "" {
		cfg.PluginPath = "/usr/lib/x86_64-linux-gnu/vpp_plugins"
	}
}

func (cfg VPPStartupConfig) Get() string {
	var b strings.Builder
	if err := startupTemplate.Execute(&b, cfg); err != nil {
		panic(err)
	}
	return b.String()
}
