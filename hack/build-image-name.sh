function get_build_hash {
  (
    (cd vpp && git ls-files -s -- Makefile build/external)
    md5sum Dockerfile.build
  ) | md5sum | awk '{print $1}'
}

: ${BUILD_IMAGE_NAME:=quay.io/travelping/upg-build}
build_hash="$(get_build_hash)"
build_image="${BUILD_IMAGE_NAME}:${build_hash}"
