#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail

if [[ ${BASH:-} ]]; then
  # not compatible with alpine's sh
  set -o errtrace
  cd "$(dirname "${BASH_SOURCE}")/.."
fi

. vpp.spec
rm -rf vpp
git clone -b "${VPP_BRANCH}" -n "${VPP_REPO}"
(
  cd vpp
  # FIXME: sometimes checkout on downstream branch fails
  # switch to VPP_BRANCH before creating downstream
  git checkout "${VPP_BRANCH}"
  git checkout -b downstream "${VPP_COMMIT}"
  git am ../vpp-patches/*
  cd src/plugins
  ln -s ../../../upf .
)
