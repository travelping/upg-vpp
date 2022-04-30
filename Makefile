.PHONY: install-hooks checkstyle ci-build image install retest test e2e retest-e2e buildenv \
version

SHELL = /bin/bash
BUILD_TYPE ?= debug
IMAGE_BASE ?= upg
TEST_VERBOSITY ?= 2
VERSION = $(shell . hack/version.sh && echo "$${UPG_GIT_VERSION}")
include vpp.spec

install-hooks:
	hack/install-hooks.sh

# avoid rebuilding part of the source each time
version:
	ver_tmp=`mktemp version-XXXXXXXX`; \
	echo "#ifndef UPG_VERSION" >"$${ver_tmp}"; \
	echo "#define UPG_VERSION \"$(VERSION)\"" >>"$${ver_tmp}"; \
	echo "#endif" >>"$${ver_tmp}"; \
	if ! cmp upf/version.h "$${ver_tmp}"; then \
	  mv "$${ver_tmp}" upf/version.h; \
	else \
	  rm -f "$${ver_tmp}"; \
	fi

# TODO: checktyle shouldn't require VPP checkout but presently it's
# needed for getting the build image tag
checkstyle:
	SKIP_VPP_SOURCE_CHECK=1 hack/buildenv.sh hack/checkstyle.sh

ci-build: version
	hack/ci-build.sh

image: version
	DOCKER_BUILDKIT=1 \
	docker build -t $(IMAGE_BASE):${BUILD_TYPE} \
	  --build-arg BUILD_TYPE=${BUILD_TYPE} \
	  --build-arg BASE=$(VPP_IMAGE_BASE)_${BUILD_TYPE} \
	  --build-arg DEVBASE=$(VPP_IMAGE_BASE)_dev_$(BUILD_TYPE) .

install: version
	hack/buildenv.sh hack/build-internal.sh install

retest:
	hack/buildenv.sh hack/run-integration-tests-internal.sh

test: version
	hack/buildenv.sh /bin/bash -c \
	  'make install && hack/run-integration-tests-internal.sh'

e2e: version
	UPG_BUILDENV_PRIVILEGED=1 hack/buildenv.sh /bin/bash -c \
	  'make install && hack/e2e.sh'

retest-e2e:
	UPG_BUILDENV_PRIVILEGED=1 hack/buildenv.sh hack/e2e.sh

buildenv: version
	UPG_BUILDENV_PRIVILEGED=1 hack/buildenv.sh

clean-buildenv:
	hack/buildenv.sh clean

genbinapi:
	hack/buildenv.sh /bin/bash -c 'make install && hack/genbinapi.sh'
