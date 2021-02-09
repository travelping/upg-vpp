#!/bin/bash -x
# TODO: remove -x above !
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

trap "sleep 10" EXIT

sysctl kernel.core_pattern="/tmp/coredump/core.%t.%e.%p"
cp /etc/vpp/startup.conf /tmp/startup.conf

echo "cpu {" >>/tmp/startup.conf
if [[ ${VPP_USE_WORKER_CORE:-} ]]; then
  # this expands ranges like 10-12,42 in the cpuset core list
  # into an array by using eval and {x..y} brace expansion
  cores=($(eval "echo $(sed 's/\([0-9]*\)-\([0-9]*\)/{\1..\2}/g;s/,/ /g' /sys/fs/cgroup/cpuset/cpuset.cpus)"))
  if (( ${#cores[@]} < 2 )); then
    echo >&2 "ERROR: need at least 2 cores"
    exit 1
  fi
  main_core=${cores[0]}
  # try to pick a non-sibling core from the rest of the list
  for ((i = 1; i < ${#cores[@]}; i++)); do
    worker_core="${cores[${i}]}"
    if ! grep -qE "\b(${main_core},${worker_core}|${worker_core},${main_core})\b" \
         /sys/devices/system/cpu/cpu*/topology/thread_siblings_list; then
      break
    fi
  done
  if (( ${i} == ${#cores[@]} )); then
    echo >&2 "ERROR: couldn't find enough cores"
    echo >&2 "ERROR: the main core ${main_core} and the worker core ${worker_core} are HT siblings!"
    if [[ ! ${VPP_TOLERATE_HT_SIBLING_CORES:-} ]]; then
      exit 1
    fi
  fi
  echo "  main-core ${main_core}" >>/tmp/startup.conf
  echo "  corelist-workers ${worker_core}" >>/tmp/startup.conf
else
  echo "  workers 0" >>/tmp/startup.conf
fi
echo "}" >>/tmp/startup.conf

/usr/bin/vpp -c /tmp/startup.conf
