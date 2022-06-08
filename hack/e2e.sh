#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

cd "$(dirname "${BASH_SOURCE}")/.."

: "${E2E_RETEST:=}"
: "${E2E_PARALLEL:=}"
: "${E2E_PARALLEL_NODES:=10}"
: "${E2E_FOCUS:=}"
: "${E2E_SKIP:=}"
: "${E2E_VERBOSE:=}"
: "${E2E_ARTIFACTS_DIR:=}"
: "${E2E_JUNIT_DIR:=}"
: "${E2E_QUICK:=}"
: "${E2E_FLAKE_ATTEMPTS:=}"
: "${E2E_TRACE:=}"
: "${E2E_DISPATCH_TRACE:=}"
: "${E2E_PAUSE_ON_ERROR:=}"
: "${E2E_MULTICORE:=}"
: "${E2E_XDP:=}"
: "${E2E_KEEP_ALL_ARTIFACTS:=}"
: "${E2E_POLLING_MODE:=}"
: "${E2E_VPP_NOT_INSTALLED:=}"
: "${E2E_NO_GDB:=}"
: "${E2E_GDBSERVER:=}"
: "${BUILD_TYPE:=debug}"

if [[ ! ${E2E_POLLING_MODE} ]]; then
  export VPP_INTERRUPT_MODE=1
fi

if [[ ${E2E_NO_GDB} ]]; then
  export VPP_NO_GDB=1
fi

if [[ ${E2E_GDBSERVER} ]]; then
  export VPP_GDBSERVER=1
fi

if grep -q '^gtp ' /proc/modules; then
  echo >&2 "* Using kernel GTP-U support for IPv4 PGW tests"
  export UPG_TEST_GTPU_KERNEL=1
else
  echo >&2 "* Kernel GTP-U support not available, using userspace GTP-U only"
fi

export UPG_TEST_QUICK="${E2E_QUICK}"
export VPP_TRACE="${E2E_TRACE}"
export VPP_DISPATCH_TRACE="${E2E_DISPATCH_TRACE}"
export VPP_MULTICORE="${E2E_MULTICORE}"
if [[ ${E2E_XDP} ]]; then
  ulimit -l 10000000
  export VPP_XDP=1
fi

if [[ ${E2E_VPP_NOT_INSTALLED} ]]; then
  case ${BUILD_TYPE} in
    debug)
      if [[ ! ${E2E_RETEST} ]]; then
        make -C vpp build
      fi
      export VPP_PATH="/vpp-src/build-root/install-vpp_debug-native/vpp/bin/vpp"
      export VPP_PLUGIN_PATH="/vpp-src/build-root/install-vpp_debug-native/vpp/lib/vpp_plugins"
      export LD_LIBRARY_PATH="$/vpp-src/build-root/install-vpp_debug-native/vpp/lib"
      ;;
    release)
      if [[ ! ${E2E_RETEST} ]]; then
        make -C vpp build-release
      fi
      export VPP_PATH="${PWD}/vpp/build-root/install-vpp-native/vpp/bin/vpp"
      export VPP_PLUGIN_PATH="${PWD}/vpp/build-root/install-vpp-native/vpp/lib/vpp_plugins"
      export LD_LIBRARY_PATH="${PWD}/vpp/build-root/install-vpp-native/vpp/lib"
      ;;
    *)
      echo >&2 "BUILD_TYPE must be either debug or release"
      ;;
  esac
  ln -fs /src/build-root/upf_plugin.so "${VPP_PLUGIN_PATH}/upf_plugin.so"
fi

cd test/e2e

ginkgo_args=(-trace -progress -reportPassed -debug)

if [[ ${E2E_VERBOSE} ]]; then
  ginkgo_args+=(-v)
fi

if [[ ${E2E_PARALLEL} ]]; then
  ginkgo_args+=(-nodes "${E2E_PARALLEL_NODES}")
fi

if [[ ${E2E_FOCUS} ]]; then
  ginkgo_args+=(-focus "${E2E_FOCUS}")
fi

if [[ ${E2E_SKIP} ]]; then
  ginkgo_args+=(-skip "${E2E_SKIP}")
fi

if [[ ${E2E_FLAKE_ATTEMPTS} ]]; then
  ginkgo_args+=(--flakeAttempts ${E2E_FLAKE_ATTEMPTS})
fi

ginkgo_args+=(--)

if [[ ${E2E_ARTIFACTS_DIR} ]]; then
  ginkgo_args+=(-artifacts-dir "${E2E_ARTIFACTS_DIR}")
fi

if [[ ${E2E_JUNIT_DIR} ]]; then
  ginkgo_args+=(-junit-output "${E2E_JUNIT_DIR}")
fi

if [[ ${E2E_PAUSE_ON_ERROR} ]]; then
  ginkgo_args+=(-pause)
fi

r=0
ginkgo "${ginkgo_args[@]}" || r=$?
if [[ ${r} != 0 && ${E2E_ARTIFACTS_DIR} ]]; then
  mv ginkgo-node-*.log "${E2E_ARTIFACTS_DIR}/" || true
fi
exit ${r}
