#!/bin/sh
set -o errexit
set -o nounset
set -x

registry="${1}"

if [ -z "${registry}" ]; then
  echo >&2 "Usage: REGISTRY_LOGIN=... REGISTRY_PASSWORD=... $0 registry_server"
  exit 1
fi

if [ -z "${REGISTRY_LOGIN}" -o -z "${REGISTRY_PASSWORD}" ]; then
  echo >&2 "Must specify REGISTRY_LOGIN and REGISTRY_PASSWORD environment vars"
  exit 1
fi

# can't use base64 -w b/c of busybox
auth="$(echo -n "${REGISTRY_LOGIN}:${REGISTRY_PASSWORD}" | base64 | tr -d \\n)"

mkdir -p "${HOME}/.docker"
cat > "${HOME}/.docker/config.json" <<EOF
{
  "auths": {
    "${registry}": {
      "auth": "${auth}"
    }
  },
  "HttpHeaders": {
    "User-Agent": "Docker-Client/18.09.8 (linux)"
  }
}
EOF

chmod 700 "${HOME}/.docker"
chmod 600 "${HOME}/.docker/config.json"
