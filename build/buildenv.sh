#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

cd "$(dirname "${BASH_SOURCE}")/.."

: ${BUILDENV:=${BUILDENV:-docker}}
: ${BUILD_TYPE:=debug}
: ${DEV_IMAGE:=${VPP_IMAGE_BASE}_dev_${BUILD_TYPE}}
: ${VPP_SRC:=}
: ${BUILDENV_EXTRA_ARGS:=${BUILDENV_EXTRA_ARGS:-}}
: ${DEVENV_BG:=}
: ${BUILDENV_WORKDIR:=/src}

function docker_buildenv {
  priv=
  if [[ ${BUILDENV_PRIVILEGED:-} ]]; then
    priv="--privileged"
  fi

  for var in $(compgen -v | grep -E '^(E2E_|LC_ALL$|LANG$)') BUILD_TYPE; do
    opts+=(-e "${var}=${!var}")
  done

  if [[ -t 0 ]]; then
    opts+=(-it)
  fi

  if [[ ${BUILDENV_EXTRA_ARGS:=} ]]; then
    opts+=(${BUILDENV_EXTRA_ARGS})
  fi

  name="vpp-build-${BUILD_TYPE}"
  if [[ ${DEVENV_BG} ]]; then
    name="vpp-build-${BUILD_TYPE}-bg"
    opts+=(-d)
  fi

  docker rm -f "${name}"
  docker run --rm --name "${name}" --shm-size 1024m \
         ${priv} \
         -v $PWD:/src:delegated -v $PWD/vpp-out:/vpp-out \
         -v ${PWD}/hack/vscode-buildenv:/src/.vscode \
         "${opts[@]}" -w "${BUILDENV_WORKDIR}" \
         "${DEV_IMAGE}" "$@"
}

case "${BUILDENV}" in
  default)
    exec "$@"
    ;;
  docker)
    docker_buildenv "$@"
    ;;
  *)
    echo >&2 "Invalid BUILDENV: ${BUILDENV}"
    ;;
esac
