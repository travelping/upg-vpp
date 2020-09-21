#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
set -x

: ${REGISTRY:=quay.io}
: ${CONTAINER_IMAGE:=travelping/upf}
: ${DOCKERFILE:=Dockerfile.devel}
: ${BUILDKITD_ADDR:=tcp://buildkitd:1234}

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
           "$@"
}

CI_COMMIT_DESCRIBE=$(git describe --always --tags --dirty --first-parent)
IMAGE_VARIANT="${CI_BUILD_NAME##*:}"
IMAGE_REPO="${REGISTRY}/${CONTAINER_IMAGE}"
IMAGE_BASE_NAME="${IMAGE_REPO}:${CI_COMMIT_REF_SLUG}"
IMAGE_COMMIT_SHA="${IMAGE_BASE_NAME}_${CI_COMMIT_SHA}_${IMAGE_VARIANT}"
IMAGE_FULL_NAME="${IMAGE_BASE_NAME}_${CI_COMMIT_DESCRIBE}_${IMAGE_VARIANT}"

case "${CI_COMMIT_REF_NAME}" in
  stable/* | feature/20* ) export LABELS="";;
  *)                       export LABELS="--label quay.expires-after=7d";;
esac

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
do_build --opt target=final-stage \
         --output type=image,name="${IMAGE_FULL_NAME}",push=true
