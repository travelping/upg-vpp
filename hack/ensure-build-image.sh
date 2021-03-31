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
: ${USE_BUILDCTL:=}
: ${BUILDKITD_ADDR:=tcp://buildkitd:1234}

. hack/build-image-name.sh

if [[ ${REGISTRY_LOGIN:-} && ${REGISTRY_PASSWORD:-} ]]; then
  echo >&2 "registry login..."
  # we don't want to include docker in the build image just to log into
  # the registry
  hack/registry-login.sh "${REGISTRY}"
fi

# TODO: >& /dev/null for 'docker manifest inspect'
if [[ ! $(docker images -q "${build_image}") ]] && ! DOCKER_CLI_EXPERIMENTAL=enabled docker manifest inspect  "${build_image}"; then
  if [[ ${USE_BUILDCTL} ]]; then
    # FIXME: can't export cache to quay.io:
    # https://github.com/moby/buildkit/issues/1440
    # --export-cache type=inline \
    # --import-cache type=registry,ref="${BUILD_IMAGE_NAME}" \
    push_opt=""
    if [[ ${PUSH_BUILD_IMAGE} ]]; then
      push_opt=",push=true"
    fi
    buildctl --addr "${BUILDKITD_ADDR}" build \
             --frontend dockerfile.v0 \
             --progress=plain \
             --local context=. \
             --local dockerfile=. \
             --opt filename=Dockerfile.build \
             --output type=image,name="${build_image}${push_opt}"
  else
    DOCKER_BUILDKIT=1 docker build -f Dockerfile.build -t "${build_image}" .
    if [[ ${PUSH_BUILD_IMAGE} ]]; then
      docker push "${build_image}"
    fi
  fi
fi
