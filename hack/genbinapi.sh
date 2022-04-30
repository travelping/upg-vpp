#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

cd "$(dirname "${BASH_SOURCE}")/.."

. vpp.spec

API_FILES=(
  upf
)
GOVPP_API_DIR="${PWD}/test/e2e/binapi"
GOVPP_API_IMPORT_PREFIX=github.com/travelping/upg-vpp/test/e2e/binapi
# export VPP_VERSION="${VPP_RELEASE}"

# cp -v ./build-root/vpp_plugins/upf/upf.api.json /usr/share/vpp/api/plugins/

cd test/e2e

go mod tidy
GOVPP_DIR=$(go list -f '{{.Dir}}' -m git.fd.io/govpp.git)

workdir="$(mktemp -d)"

if [[ ! ${workdir} || ! -d ${workdir} ]]; then
  echo >&2 "Could not create temp dir"
  exit 1
fi

function cleanup {
  rm -rf "${workdir}"
}

trap cleanup EXIT

function make_binapi_generator ()
{
  target_dir="${PWD}/bin"
  mkdir -p "${target_dir}"
  (
    cd "${GOVPP_DIR}"
    go build -o "${target_dir}" ./cmd/binapi-generator
  )
}

function extract_binapi_files ()
{
  if [[ $(uname) = Linux && -d /src && -d /usr/share/vpp/api ]]; then
    # inside the devenv container
    tar -C /usr/share/vpp/api -c .
  else
    docker run --entrypoint /bin/tar "${VPP_IMAGE_BASE}_dev_debug" \
           -C /usr/share/vpp/api -c .
  fi |
    tar -C "${workdir}" -xv --strip-components=1
}

function generate_govpp_apis ()
{
  mkdir -p "${GOVPP_API_DIR}"
  bin/binapi-generator \
    --input-dir="${workdir}" \
    --output-dir="${GOVPP_API_DIR}" \
    --import-prefix="${GOVPP_API_IMPORT_PREFIX}" \
    --no-source-path-info \
    --no-version-info \
    "${API_FILES[@]}"
}

make_binapi_generator
extract_binapi_files
generate_govpp_apis
