#!/bin/bash

set -e

CI_BUILD="${CI_BUILD:-}"

if [[ CI_BUILD -ne 1 ]]; then
    git submodule update --init --recursive
fi

cd vpp-base
build/ensure-initialized.sh

