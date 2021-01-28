IMAGE_BASE ?= upg
TEST_VERBOSITY ?= 2

install-hooks:
	hack/install-hooks.sh

vpp:
	hack/update-vpp.sh

# this will run regardless of existence of the 'vpp' directory
update-vpp:
	hack/update-vpp.sh

ci-build: vpp
	hack/ci-build.sh

ensure-build-image: vpp
	hack/ensure-build-image.sh

update-build-image-tag: vpp
	hack/update-build-image-tag.sh

image-debug: vpp
	docker buildx build -t $(IMAGE_BASE):debug \
	  -f Dockerfile.devel .

image-release: vpp
	docker buildx build -t $(IMAGE_BASE):release \
	  -f Dockerfile .

test-debug:
	hack/buildenv.sh make test-debug TEST=test_upf V=$(TEST_VERBOSITY) \
	  EXTERN_TESTS=../../upf/test

test-release:
	hack/buildenv.sh make test TEST=test_upf V=$(TEST_VERBOSITY) \
	  EXTERN_TESTS=../../upf/test

retest-debug:
	hack/buildenv.sh make retest-debug TEST=test_upf V=$(TEST_VERBOSITY) \
	  EXTERN_TESTS=../../upf/test

retest-release:
	hack/buildenv.sh make retest TEST=test_upf V=$(TEST_VERBOSITY) \
	  EXTERN_TESTS=../../upf/test

e2e-debug:
	UPG_BUILDENV_PRIVILEGED=1 \
	E2E_TARGET=debug \
	hack/buildenv.sh ../hack/e2e.sh

e2e-release:
	UPG_BUILDENV_PRIVILEGED=1 \
	E2E_TARGET=release \
	hack/buildenv.sh ../hack/e2e.sh

buildenv:
	UPG_BUILDENV_PRIVILEGED=1 hack/buildenv.sh
