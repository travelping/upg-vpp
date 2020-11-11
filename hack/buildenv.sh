#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

cd "$(dirname "${BASH_SOURCE}")/.."

if [[ ! ${SKIP_VPP_SOURCE_CHECK:-} && ! -e vpp/Makefile ]]; then
  echo >&2 "Please run 'make update-vpp'"
  exit 1
fi

priv=
if [[ ${UPG_BUILDENV_PRIVILEGED:-} ]]; then
  priv="--privileged"
fi

if [[ ! ${UPG_DOCKER_BUILDENV:-} ]]; then
  cd vpp
  exec "$@"
else
  . hack/build-image-name.sh
  docker run -it --rm --name vpp-build --shm-size 1024m \
         ${priv} \
         -v $PWD:/src:delegated \
         -v $PWD/vpp-out:/vpp-out \
         -e LC_ALL=C.UTF-8 \
         -e LANG=C.UTF-8 \
         -e E2E_RETEST="${E2E_RETEST:=}" \
         -e E2E_PARALLEL="${E2E_PARALLEL:-}" \
         -e E2E_PARALLEL_NODES="${E2E_PARALLEL_NODES:-}" \
         -e E2E_FOCUS="${E2E_FOCUS:-}" \
         -e E2E_TARGET="${E2E_TARGET:-}" \
         -e E2E_ARTIFACTS_DIR="${E2E_ARTIFACTS_DIR:-}" \
         -e E2E_JUNIT_DIR="${E2E_JUNIT_DIR:-}" \
         -w /src/vpp \
         "${build_image}" \
         "$@"
fi
