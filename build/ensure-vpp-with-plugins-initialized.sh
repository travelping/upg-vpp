#!/bin/bash

set -e

SKIP_DEPS="${SKIP_DEPS:-0}"

git submodule update --init --recursive

cd vpp-base
build/ensure-initialized.sh
