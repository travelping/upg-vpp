#!/bin/bash

set -o nounset

: ${UPG_REPO:="quay.io/travelping/upg-vpp"}
: ${UPG_HASH:=$(git rev-parse HEAD:upf-plugin)}
: ${BUILD_TYPE:=debug}

. "$(dirname "${BASH_SOURCE}")/get-images-names.sh"

SCRIPT_DIR="$(dirname "${BASH_SOURCE}")"

"${SCRIPT_DIR}/../vpp-base/build/try-pull-docker-image.sh" "${IMAGE_HASH_NAME}"
PULL_RES="${?}"
if [[ "${PULL_RES}" -eq 0 ]]; then
    "${SCRIPT_DIR}/../vpp-base/build/try-pull-docker-image.sh" "${DEV_IMAGE_HASH_NAME}"
    PULL_RES="${?}"
fi

case "${PULL_RES}" in
0)
    echo "image_to_retag_present=true" >> "${GITHUB_OUTPUT}"
    echo "${BUILD_TYPE}_image_to_retag_present=true" >> "${GITHUB_OUTPUT}"
    ;;
2)
    echo "image_to_retag_present=false" >> "${GITHUB_OUTPUT}"
    echo "${BUILD_TYPE}_image_to_retag_present=false" >> "${GITHUB_OUTPUT}"
    ;;
*)
    exit 1
    ;;
esac

