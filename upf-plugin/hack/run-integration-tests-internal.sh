#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

cd "$(dirname "${BASH_SOURCE}")/.."

make -C /vpp-src/test \
     VPP_PLUGIN_PATH=/usr/lib/x86_64-linux-gnu/vpp_plugins \
     VPP_INSTALL_PATH=/usr retest \
     WS_ROOT=/vpp-src \
     BR=/vpp-src/build-root \
     TEST_DIR=/tmp \
     TEST="${TEST:-${E2E_TEST:-test_upf}}" V=2 \
     EXTERN_TESTS=/src/upf-plugin/upf/test \
     RND_SEED=$(python3 -c 'import time; print(time.time())') \
     VPP_WS_DIR=/usr \
     TEST_PLUGIN_PATH_ARGS="--vpp /usr/bin/vpp --vpp-plugin-dir /usr/lib/x86_64-linux-gnu/vpp_plugins --vpp-install-dir /usr"
