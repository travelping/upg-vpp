#!/bin/bash

set -o errexit
set -o nounset

: ${BUILD_TYPE:=debug}
: ${UPG_REPO:="quay.io/travelping/upg-vpp"}
: ${UPG_HASH:=$(git rev-parse HEAD:upf-plugin)}

. "$(dirname "${BASH_SOURCE}")/get-images-names.sh"

RELEASE_TAG="${GITHUB_REF##*/}"
RELEASE_IMAGE_NAME="${UPG_REPO}:${RELEASE_TAG}_${BUILD_TYPE}"
DEV_RELEASE_IMAGE_NAME="${UPG_REPO}:${RELEASE_TAG}_dev_${BUILD_TYPE}"

QUAY_IO_IMAGE_EXPIRES_AFTER="$(docker image inspect "${IMAGE_HASH_NAME}" | jq -r '.[0].Config.Labels."quay.expires-after"')"
if [[ "${QUAY_IO_IMAGE_EXPIRES_AFTER}" == null ]]; then
    docker tag "${IMAGE_HASH_NAME}" "${RELEASE_IMAGE_NAME}"
else
    echo "FROM ${IMAGE_HASH_NAME}" | docker buildx build -t "${RELEASE_IMAGE_NAME}" --label "quay.expires-after=" -
fi

docker push "${RELEASE_IMAGE_NAME}"

QUAY_IO_IMAGE_EXPIRES_AFTER="$(docker image inspect "${DEV_IMAGE_HASH_NAME}" | jq -r '.[0].Config.Labels."quay.expires-after"')"
if [[ "${QUAY_IO_IMAGE_EXPIRES_AFTER}" == null ]]; then
    docker tag "${DEV_IMAGE_HASH_NAME}" "${DEV_RELEASE_IMAGE_NAME}"
else
    echo "FROM ${DEV_IMAGE_HASH_NAME}" | docker buildx build -t "${DEV_RELEASE_IMAGE_NAME}" --label "quay.expires-after=" -
fi

docker push "${DEV_RELEASE_IMAGE_NAME}"

