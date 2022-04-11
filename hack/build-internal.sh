#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

: ${BUILD_TYPE:=release}

cd "$(dirname "${BASH_SOURCE}")/.."

mkdir -p build-root
cd build-root

case "${BUILD_TYPE}" in
  debug)
    btype="Debug"
    ;;
  release)
    btype="Release"
    ;;
  *) echo >&2 "Bad BUILD_TYPE: ${BUILD_TYPE}"
     ;;
esac

opts=(-DCMAKE_BUILD_TYPE="${btype}" -DCMAKE_INSTALL_PREFIX=/usr)
if [[ ${SANITIZE_ADDR} ]]; then
  opts+=(-DVPP_ENABLE_SANITIZE_ADDR=1)
fi
cmake "${opts[@]}" /src

make -C /src/build-root "$@"
