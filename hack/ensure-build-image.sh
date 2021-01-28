#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail

if [[ ${BASH:-} ]]; then
  # not compatible with alpine's sh
  set -o errtrace
  cd "$(dirname "${BASH_SOURCE}")/.."
fi

if [[ ! -e vpp/Makefile ]]; then
  echo >&2 "Please run 'make update-vpp'"
  exit 1
fi

: ${PUSH_BUILD_IMAGE:=}

. hack/build-image-name.sh

if [[ ! $(docker images -q "${build_image}") ]] && ! docker pull "${build_image}"; then
    if [[ ${PUSH_BUILD_IMAGE} ]]; then
	push="--push"
    fi
    docker buildx build -f Dockerfile.build -t "${build_image}" ${push} .
fi
