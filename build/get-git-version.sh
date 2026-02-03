#!/bin/bash

COMMIT=$(git rev-parse "HEAD^{commit}")
args=("--long" "--tags" "--abbrev=8" "--match=v*" "${COMMIT}")
git describe "${args[@]}" 2>/dev/null || echo "v0.0.0-0-g0"

