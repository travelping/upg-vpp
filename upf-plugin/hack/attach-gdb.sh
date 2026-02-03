#!/bin/bash
# this script tries to attach to a gdbserver

# wait for gdbserver to start
while ! pidof gdbserver >& /dev/null; do sleep 1; done
nsenter <&0 -t $(pidof gdbserver) -n gdb "$@"