#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

: ${BASE_REPO:="quay.io/travelping/fpp-vpp"}
: ${BASE_TAG:=local}
: ${UPG_REPO:="quay.io/travelping/upg-vpp"}
: ${UPG_HASH:=$(git rev-parse HEAD:upf-plugin)}
: ${BUILD_TYPE:=debug}
: ${DO_PUSH:=}
: ${DOCKERFILE:=Dockerfile}
: ${QUAY_IO_IMAGE_EXPIRES_AFTER:=7d}

BASE_IMAGE_NAME="${BASE_REPO}:${BASE_TAG}_${BUILD_TYPE}"
BASE_DEV_IMAGE_NAME="${BASE_REPO}:${BASE_TAG}_dev_${BUILD_TYPE}"
. "$(dirname "${BASH_SOURCE}")/get-images-names.sh"
PACKAGES_VERSION="$(build/get-git-version.sh)"

BUILD_OPTS=()
if [[ -n "${QUAY_IO_IMAGE_EXPIRES_AFTER}" ]]; then
    BUILD_OPTS+=(--label "quay.expires-after=${QUAY_IO_IMAGE_EXPIRES_AFTER}")
fi

function do_build {
  set -x
  docker buildx build \
           --progress=plain \
           --file "${DOCKERFILE}" \
           --build-arg VER=${PACKAGES_VERSION} \
           --build-arg BUILD_TYPE=${BUILD_TYPE} \
           --build-arg BASE=${BASE_IMAGE_NAME} \
           --build-arg DEVBASE=${BASE_DEV_IMAGE_NAME} \
           "${BUILD_OPTS[@]}" \
           . "$@"
  set +x
}

cd upf-plugin

push=""
if [[ "${DO_PUSH,,}" == "y" ]]; then
    push=",push=true"
fi

echo >&2 "Building the dev image from ${DOCKERFILE} ..."
do_build --target=dev-stage \
         --output type="image,\"name=${DEV_IMAGE_NAME}\"${push}"

docker tag "${DEV_IMAGE_NAME}" "${DEV_IMAGE_HASH_NAME}"
if [[ "${DO_PUSH,,}" == "y" ]]; then
    docker push "${DEV_IMAGE_HASH_NAME}"
fi

echo >&2 "Building the image from ${DOCKERFILE} ..."
do_build --target=final-stage \
         --output type="image,\"name=${FINAL_IMAGE_NAME}\"${push}"

docker tag "${FINAL_IMAGE_NAME}" "${IMAGE_HASH_NAME}"
if [[ "${DO_PUSH,,}" == "y" ]]; then
    docker push "${IMAGE_HASH_NAME}"
fi

