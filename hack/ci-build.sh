#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
set -x

: ${REGISTRY:=quay.io}
: ${CONTAINER_IMAGE:=travelping/upg-vpp}
: ${DOCKERFILE:=Dockerfile.devel}

. vpp.spec
function do_build {
    docker buildx build \
           --build-arg BUILD_IMAGE="${BUILD_IMAGE}" \
           --label vpp.release="${VPP_RELEASE}" \
           --label vpp.commit="${VPP_COMMIT}" \
           "$@" \
           -f ${DOCKERFILE} .
}

IMAGE_VARIANT="${CI_BUILD_NAME##*:}"
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

#echo >&2 "Create builder ..."
#docker buildx create \
#       --append \
#       --name upg \
#       --driver-opt env.BUILDKIT_STEP_LOG_MAX_SIZE=10000000,env.BUILDKIT_STEP_LOG_MAX_SPEED=100000000 \
#       --use
#docker buildx ls

echo >&2 "Building VPP and extracting the artifacts ..."
rm -rf /tmp/_out
mkdir /tmp/_out
do_build --target=artifacts --output type=local,dest=/tmp/_out

echo >&2 "Building the image from ${DOCKERFILE} ..."
do_build --target=final-stage \
         --tag "${IMAGE_FULL_NAME}" --push
