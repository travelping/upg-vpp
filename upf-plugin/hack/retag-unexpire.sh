#!/bin/bash
# Retag a docker image in the registry, removing quay.io specific expiration label
# (quay.expires-after) if it's present.
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

if [[ $# < 4 ]]; then
  echo "Usage: $0 registry image oldtag newtag"
  exit 1
fi

registry="$1"
image="$2"
oldtag="$3"
newtag="$4"

manifest=$(mktemp /tmp/retag-manifest.XXXXXX)
config=$(mktemp /tmp/retag-config.XXXXXX)
trap 'rm -- "${manifest}" "${config}"' INT TERM HUP EXIT

function do_curl {
  local url="$1"
  shift
  if [[ ${url} =~ ^/ ]]; then
    url="https://${registry}/v2/${image}${url}"
  fi
  curl -sSL -H "Authorization: Bearer $token" \
       -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
       "${url}" "$@"
}

# Get the auth token
token="$(curl -s -u "${REGISTRY_LOGIN}:${REGISTRY_PASSWORD}" "https://${registry}/v2/auth?service=${registry}&scope=repository:${image}:push" | jq -r .token)"

# Download the image manifest
do_curl "/manifests/${oldtag}">"${manifest}"
# Extract image config digest from the manifest
config_digest=$(cat "${manifest}" | jq -r .config.digest)

# Download the image config, removing expiration label from it
do_curl "/blobs/${config_digest}" | jq 'del(.config.Labels["quay.expires-after"])' > "${config}"

# Prepare to upload the blob with new config.
# Get last location: header after redirect
upload_location="$(do_curl "/blobs/uploads" -i -X POST | grep -i '^Location:' | tail -1 | sed 's/^[^ ]*: *//' | tr -d '[:space:]')"
if [[ ${upload_location} =~ .*\? ]]; then
  upload_location="${upload_location}&"
else
  upload_location="${upload_location}?"
fi

new_config_digest="sha256:$(sha256sum "${config}" | cut -d' ' -f1)"
new_config_size="$(wc -c "${config}"|awk '{print $1}')"

# Upload the new config
do_curl "${upload_location}digest=${new_config_digest}" -T "${config}"

# Upload the manifest with replaced config using the new tag
do_curl "/manifests/${newtag}" -X PUT \
        -H 'Content-Type: application/vnd.docker.distribution.manifest.v2+json' \
        -d @<(jq ".config.digest|=\"${new_config_digest}\"|.config.size=${new_config_size}" "${manifest}")

echo
