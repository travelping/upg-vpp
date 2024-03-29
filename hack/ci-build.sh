#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

: ${REGISTRY:=quay.io}
: ${IMAGE_NAME:=travelping/upg-vpp}
: ${DOCKERFILE:=}
: ${BUILD_TYPE:=debug}
: ${NO_PUSH:=}
: ${IMAGE_EXPIRES_AFTER:=7d}
: ${DOCKERFILE:=Dockerfile}

. vpp.spec

function do_build {
  # TODO: build branch images and export cache to the corresponding branch image
  # --export-cache type=inline \
  # --import-cache type=registry,ref="${IMAGE_BASE_NAME}" \
  set -x
  docker buildx build \
    --progress plain \
    --file "${DOCKERFILE}" \
    --build-arg BUILD_TYPE=${BUILD_TYPE} \
    --build-arg BASE=${VPP_IMAGE_BASE}_${BUILD_TYPE} \
    --build-arg DEVBASE=${VPP_IMAGE_BASE}_dev_${BUILD_TYPE} \
    --label "quay.expires-after=${IMAGE_EXPIRES_AFTER}" \
    . "$@"
   set +x
}

IMAGE_BASE_NAME="${REGISTRY}/${IMAGE_NAME}"
. hack/version.sh
IMAGE_BASE_TAG="${UPG_IMAGE_TAG}"
DEV_IMAGE_NAME="${IMAGE_BASE_NAME}:${IMAGE_BASE_TAG}_dev_${BUILD_TYPE}"
FINAL_IMAGE_NAME="${IMAGE_BASE_NAME}:${IMAGE_BASE_TAG}_${BUILD_TYPE}"

echo >&2 "Building VPP and extracting the artifacts ..."
rm -rf /tmp/_out
mkdir /tmp/_out
do_build --target=artifacts --output type=local,dest=/tmp/_out

echo >&2 "Building the dev image from ${DOCKERFILE} ..."
push=",push=true"
if [[ ${NO_PUSH} ]]; then
  push=""
fi
do_build --target=dev-stage \
         --output type="image,\"name=${DEV_IMAGE_NAME}\"${push}"

echo >&2 "Building the final image from ${DOCKERFILE} ..."
do_build --target=final-stage \
         --output type="image,\"name=${FINAL_IMAGE_NAME}\"${push}"

echo "${DEV_IMAGE_NAME}" > "image-dev-${BUILD_TYPE}.txt"
echo "${FINAL_IMAGE_NAME}" > "image-${BUILD_TYPE}.txt"
