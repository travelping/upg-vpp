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
: "${E2E_TARGET:=debug}"
: "${E2E_ARTIFACTS_DIR:=}"
: "${E2E_JUNIT_DIR:=}"
: "${E2E_QUICK:=}"
: "${E2E_FLAKE_ATTEMPTS:=}"

if grep -q '^gtp ' /proc/modules; then
  echo >&2 "* Using kernel GTP-U support for IPv4 PGW tests"
  export UPG_TEST_GTPU_KERNEL=1
else
  echo >&2 "* Kernel GTP-U support not available, using userspace GTP-U only"
fi

export UPG_TEST_QUICK="${E2E_QUICK}"

case ${E2E_TARGET} in
  debug)
    if [[ ! ${E2E_RETEST} ]]; then
      make -C vpp build
    fi
    export VPP_PATH="${PWD}/vpp/build-root/install-vpp_debug-native/vpp/bin/vpp"
    export VPP_PLUGIN_PATH="${PWD}/vpp/build-root/install-vpp_debug-native/vpp/lib/vpp_plugins"
    export LD_LIBRARY_PATH="${PWD}/vpp/build-root/install-vpp_debug-native/vpp/lib"
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
    echo >&2 "E2E_TARGET must be either debug or release"
    ;;
esac

cd test/e2e

ginkgo_args=(-trace -progress -reportPassed)

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

ginkgo "${ginkgo_args[@]}"
