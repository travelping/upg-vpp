#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

cd "$(dirname "${BASH_SOURCE}")/.."

: "${BUILD_IMAGE_NAME:=quay.io/travelping/upg-build}"

. hack/build-image-name.sh
files=(Dockerfile Dockerfile.devel)

verify=
if [[ ${1:-} = "-verify" ]]; then
  verify=1
fi

sed_cmd="s@\(FROM \|image: \)quay\.io/[^ ]*\(.*# XX_DO_NOT_REMOVE_THIS_COMMENT\|.* AS build-stage\)@\1${build_image}\2@"
if [[ ${verify} ]]; then
  for f in "${files[@]}"; do
    if ! cmp -s "${f}" <(sed "${sed_cmd}" "${f}"); then
      echo >&2 "Build image tag not up to date ($f), please run"
      echo >&2 "hack/update-build-image-tag.sh"
      echo >&2 "(without arguments)"
      exit 1
    fi
  done
else
  sed -i "${sed_cmd}" "${files[@]}"
fi
