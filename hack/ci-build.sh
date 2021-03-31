#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

: ${REGISTRY:=quay.io}
: ${CONTAINER_IMAGE:=travelping/upg-vpp}
: ${DOCKERFILE:=}
: ${BUILDKITD_ADDR:=tcp://buildkitd:1234}
: ${IMAGE_VARIANT:=debug}
: ${NO_PUSH:=}

if [[ ! ${DOCKERFILE} ]]; then
  DOCKERFILE="Dockerfile"
  if [[ ${IMAGE_VARIANT} = "debug" ]]; then
    DOCKERFILE="Dockerfile.devel"
  fi
fi

. vpp.spec
function do_build {
  # FIXME: can't export cache to quay.io:
  # https://github.com/moby/buildkit/issues/1440
  # --export-cache type=inline \
  # --import-cache type=registry,ref="${IMAGE_REPO}" \
  buildctl --addr "${BUILDKITD_ADDR}" build \
           --frontend dockerfile.v0 \
           --progress=plain \
           --local context=. \
           --local dockerfile=. \
           --opt filename="${DOCKERFILE}" \
           --opt label:vpp.release="${VPP_RELEASE}" \
           --opt label:vpp.commit="${VPP_COMMIT}" \
           "$@"
}

IMAGE_BASE_NAME=${REGISTRY}/${IMAGE_NAME}
. hack/version.sh
IMAGE_BASE_TAG=${UPG_IMAGE_TAG}
IMAGE_FULL_NAME=${IMAGE_BASE_NAME}:${IMAGE_BASE_TAG}_${IMAGE_VARIANT}

# TODO: reenable this
# case "${CI_COMMIT_REF_NAME}" in
#   stable/* | feature/20* ) export LABELS="";;
#   *)                       export LABELS="--label quay.expires-after=7d";;
# esac

if [[ ${REGISTRY_LOGIN:-} && ${REGISTRY_PASSWORD:-} ]]; then
  echo >&2 "registry login..."
  # we don't want to include docker in the build image just to log into
  # the registry
  hack/registry-login.sh "${REGISTRY}"
fi

echo >&2 "Building VPP and extracting the artifacts ..."
rm -rf /tmp/_out
mkdir /tmp/_out
do_build --opt target=artifacts --output type=local,dest=/tmp/_out

echo >&2 "Building the image from ${DOCKERFILE} ..."
push=",push=true"
if [[ ${NO_PUSH} ]]; then
  push=""
fi
do_build --opt target=final-stage \
         --output type=image,name="${IMAGE_FULL_NAME}""${push}"
