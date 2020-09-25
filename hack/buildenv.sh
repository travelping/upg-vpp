#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

cd "$(dirname "${BASH_SOURCE}")/.."

if [[ ! -e vpp/Makefile ]]; then
  echo >&2 "Please run 'make update-vpp'"
  exit 1
fi

if [[ ${UPF_NO_DOCKER_BUILDENV:-} ]]; then
  cd vpp
  exec "$@"
else
  . hack/build-image-name.sh
  docker run -it --rm --name vpp-build --shm-size 1024m \
         -v $PWD:/src:delegated \
         -v $PWD/vpp-out:/vpp-out \
         -e LC_ALL=C.UTF-8 -e LANG=C.UTF-8 \
         -e UPF_NO_DOCKER_BUILDENV=1 \
         -w /src/vpp \
         "${build_image}" \
         "$@"
fi
