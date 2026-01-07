#!/usr/bin/env bash

# Based on https://github.com/kubernetes/kubernetes/blob/6b1d1ccbf5a6ff19e48915bdc8932d03ecd46c9e/hack/lib/version.sh
# Copyright 2014 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Grovels through git to set a set of env variables.
vpp::version::get_version_vars() {
    # Use git describe to find the version based on tags.
    if [[ -n ${VPP_GIT_VERSION-} ]] || VPP_GIT_VERSION=$("$(dirname "${BASH_SOURCE}")/get-git-version.sh"); then
      # This translates the "git describe" to an actual semver.org
      # compatible semantic version that looks something like this:
      #   v1.1.0-alpha.0.6+84c76d11
      #
      # TODO: We continue calling this "git version" because so many
      # downstream consumers are expecting it there.
      #
      # These regexes are painful enough in sed...
      # We don't want to do them in pure shell, so disable SC2001
      # shellcheck disable=SC2001
      DASHES_IN_VERSION=$(echo "${VPP_GIT_VERSION}" | sed "s/[^-]//g")
      if [[ "${DASHES_IN_VERSION}" == "---" ]] ; then
        # shellcheck disable=SC2001
        # We have distance to subversion (v1.1.0-subversion-1-gCommitHash)
        VPP_GIT_VERSION=$(echo "${VPP_GIT_VERSION}" | sed "s/-\([0-9]\{1,\}\)-g\([0-9a-f]\{8\}\)$/.\1\+\2/")
      elif [[ "${DASHES_IN_VERSION}" == "--" ]] ; then
        # shellcheck disable=SC2001
        # We have distance to base tag (v1.1.0-1-gCommitHash)
        VPP_GIT_VERSION=$(echo "${VPP_GIT_VERSION}" | sed "s/-g\([0-9a-f]\{8\}\)$/+\1/")
      fi

      # Try to match the "git describe" output to a regex to try to extract
      # the "major" and "minor" versions and whether this is the exact tagged
      # version or whether the tree is between two tagged versions.
      if [[ "${VPP_GIT_VERSION}" =~ ^v([0-9]+)\.([0-9]+)(\.[0-9]+)?([-].*)?([+].*)?$ ]]; then
        VPP_GIT_MAJOR=${BASH_REMATCH[1]}
        VPP_GIT_MINOR=${BASH_REMATCH[2]}
        if [[ -n "${BASH_REMATCH[4]}" ]]; then
          VPP_GIT_MINOR+="+"
        fi
      fi

      # If VPP_GIT_VERSION is not a valid Semantic Version, then refuse to build.
      if ! [[ "${VPP_GIT_VERSION}" =~ ^v([0-9]+)\.([0-9]+)(\.[0-9]+)?(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
          echo "VPP_GIT_VERSION should be a valid Semantic Version. Current value: ${VPP_GIT_VERSION}"
          echo "Please see more details here: https://semver.org"
          exit 1
      fi
    fi
}

if [ $(uname) = Darwin ]; then
  readlinkf(){ perl -MCwd -e 'print Cwd::abs_path shift' "$1";}
else
  readlinkf(){ readlink -f "$1"; }
fi
VPP_ROOT="$(cd $(dirname "$(readlinkf "${BASH_SOURCE}")")/..; pwd)"

vpp::version::get_version_vars

if [[ ${GITHUB_REF:-} =~ refs/heads/(.*) ]]; then
  branch="${BASH_REMATCH[1]}"
else
  branch="$(git rev-parse --abbrev-ref HEAD)"
fi

if [ ${branch} = main -o ${branch} = HEAD ]; then
  branch_prefix=""
else
  branch_prefix="$(echo ${branch} | tr / -)-"
fi

VPP_IMAGE_TAG=${branch_prefix}$(echo ${VPP_GIT_VERSION} | tr + -)
