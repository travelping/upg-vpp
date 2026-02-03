.PHONY: install-hooks checkstyle ci-build image install retest test e2e retest-e2e version

SHELL = /bin/bash
BUILD_TYPE ?= debug
IMAGE_BASE ?= upg
TEST_VERBOSITY ?= 2
BINARY_VERSION = $(shell . ../build/get-project-version.sh && echo "$${VPP_GIT_VERSION}")
VPP_IMAGE_BASE ?= vpp-base:local
PACKAGES_VERSION := $(shell ../build/get-git-version.sh)

install-hooks:
	hack/install-hooks.sh

# avoid rebuilding part of the source each time
version:
	ver_tmp=`mktemp version-XXXXXXXX`; \
	echo "#ifndef UPG_VERSION" >"$${ver_tmp}"; \
	echo "#define UPG_VERSION \"$(BINARY_VERSION)\"" >>"$${ver_tmp}"; \
	echo "#endif" >>"$${ver_tmp}"; \
	if ! cmp upf/version.h "$${ver_tmp}"; then \
	  mv "$${ver_tmp}" upf/version.h; \
	else \
	  rm -f "$${ver_tmp}"; \
	fi

checkstyle:
	git ls-files | grep -e "\\.[c|h]$$" | xargs clang-format-11 -n --Werror

image: version
	DOCKER_BUILDKIT=1 \
	docker build -t $(IMAGE_BASE):${BUILD_TYPE} \
	  --build-arg VER=${PACKAGES_VERSION} \
	  --build-arg BUILD_TYPE=${BUILD_TYPE} \
	  --build-arg BASE=$(VPP_IMAGE_BASE)_${BUILD_TYPE} \
	  --build-arg DEVBASE=$(VPP_IMAGE_BASE)_dev_$(BUILD_TYPE) .

install: version
	BUILD_TYPE=$(BUILD_TYPE) VER=${PACKAGES_VERSION} hack/build-internal.sh install

retest:
	hack/run-integration-tests-internal.sh

test: version
	BUILD_TYPE=$(BUILD_TYPE) VER=${PACKAGES_VERSION} /bin/bash -c \
	  'make install && hack/run-integration-tests-internal.sh'

e2e: version
	BUILD_TYPE=$(BUILD_TYPE) VER=${PACKAGES_VERSION} /bin/bash -c \
	  'make install && hack/e2e.sh'

retest-e2e:
	hack/e2e.sh

genbinapi:
	VER=${PACKAGES_VERSION} VPP_IMAGE_BASE=${VPP_IMAGE_BASE} \
		/bin/bash -c 'make install && hack/genbinapi.sh'

artifacts: version
	docker build -t $(IMAGE_BASE):${BUILD_TYPE}_artifacts \
	  --build-arg VER=${PACKAGES_VERSION} \
	  --build-arg BUILD_TYPE=${BUILD_TYPE} \
	  --build-arg BASE=$(VPP_IMAGE_BASE)_${BUILD_TYPE} \
	  --build-arg DEVBASE=$(VPP_IMAGE_BASE)_dev_$(BUILD_TYPE) \
	  --target=artifacts \
	  .

debs: version
	mkdir -p ../.out && \
	docker buildx build \
	  --build-arg VER=${PACKAGES_VERSION} \
	  --build-arg BUILD_TYPE=${BUILD_TYPE} \
	  --build-arg BASE=$(VPP_IMAGE_BASE)_${BUILD_TYPE} \
	  --build-arg DEVBASE=$(VPP_IMAGE_BASE)_dev_$(BUILD_TYPE) \
	  --target=artifacts \
	  --output type=local,dest=../.out \
	  .
