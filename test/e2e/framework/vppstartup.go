package framework

var vppStartup = `
unix {
  nodaemon
  log /tmp/vpp.log
  coredump-size unlimited
  full-coredump
  gid vpp
  interactive
  cli-listen /run/vpp/cli.sock
}

socksvr {
  default
}

api-trace {
  on
}

api-segment {
  gid vpp
}

cpu {
  workers 0
}

statseg {
  size 512M
}

plugins {
  path /usr/lib/x86_64-linux-gnu/vpp_plugins/
  plugin dpdk_plugin.so { disable }
}

`

// vlib {
// 	elog-events 10000000
// 	elog-post-mortem-dump
// }

// TODO: proper CPU pinning
