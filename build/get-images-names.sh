#!/bin/bash

set -o nounset

: ${UPG_REPO:="quay.io/travelping/upg-vpp"}
: ${UPG_HASH:=$(git rev-parse HEAD:upf-plugin)}
: ${BUILD_TYPE:=debug}

IMAGE_HASH_NAME="${UPG_REPO}:${BUILD_TYPE}-sha-${UPG_HASH}"
DEV_IMAGE_HASH_NAME="${UPG_REPO}:dev-${BUILD_TYPE}-sha-${UPG_HASH}"

. "$(dirname "${BASH_SOURCE}")/get-project-version.sh"
IMAGE_BASE_TAG="${VPP_IMAGE_TAG}"
FINAL_IMAGE_NAME="${UPG_REPO}:${IMAGE_BASE_TAG}_${BUILD_TYPE}"
DEV_IMAGE_NAME="${UPG_REPO}:${IMAGE_BASE_TAG}_dev_${BUILD_TYPE}"
