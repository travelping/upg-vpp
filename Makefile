IMAGE_BASE ?= upf
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
	bash -x hack/ensure-build-image.sh

update-build-image-tag: vpp
	hack/update-build-image-tag.sh

image-debug: vpp
	DOCKER_BUILDKIT=1 \
	docker build -t $(IMAGE_BASE):debug \
	  -f Dockerfile.devel .

image-release: vpp
	DOCKER_BUILDKIT=1 \
	docker build -t $(IMAGE_BASE):release \
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

buildenv:
	hack/buildenv.sh
