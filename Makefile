.PHONY: image test e2e debs buildenv initialize vpp-base

BUILD_TYPE ?= debug
CI_BUILD ?= 0
DO_PUSH ?= n

BASE_REPO ?= quay.io/travelping/fpp-vpp
BASE_TAG ?= local
BUILDER_REPO ?= quay.io/travelping/vpp-builder
QUAY_IO_IMAGE_EXPIRES_AFTER ?=

UPG_REPO ?= quay.io/travelping/cennso-dev/upg-vpp

image: vpp-base
ifeq ($(CI_BUILD), 1)
	BASE_TAG=${BASE_TAG} BASE_REPO=${BASE_REPO} \
	BUILD_TYPE=${BUILD_TYPE} DO_PUSH=${DO_PUSH} \
	UPG_REPO=${UPG_REPO} \
	QUAY_IO_IMAGE_EXPIRES_AFTER=${QUAY_IO_IMAGE_EXPIRES_AFTER} \
	build/ci-build.sh
else
	cd upf-plugin && \
	BUILD_TYPE=${BUILD_TYPE} \
	IMAGE_BASE=${UPG_REPO} \
	VPP_IMAGE_BASE=${BASE_REPO}:${BASE_TAG} \
	$(MAKE) image
endif

vpp-base: initialize
	cd vpp-base && \
	BASE_TAG=${BASE_TAG} BASE_REPO=${BASE_REPO} \
	BUILD_TYPE=${BUILD_TYPE} CI_BUILD=${CI_BUILD} \
	BUILDER_REPO=${BUILDER_REPO} \
	$(MAKE) image

initialize:
	build/ensure-vpp-with-plugins-initialized.sh
	cd upf-plugin && $(MAKE) version

buildenv: vpp-base
	VPP_IMAGE_BASE=${BASE_REPO}:${BASE_TAG} BUILDENV_PRIVILEGED=1 BUILDENV_WORKDIR=/src/upf-plugin build/buildenv.sh

ifeq ($(CI_BUILD), 1)
  BUILDENV_DEPS =
else
  BUILDENV_DEPS = vpp-base
endif

test: $(BUILDENV_DEPS)
	VPP_IMAGE_BASE=${BASE_REPO}:${BASE_TAG} BUILDENV_PRIVILEGED=1 build/buildenv.sh \
	bash -c "cd upf-plugin && $(MAKE) test"

e2e: $(BUILDENV_DEPS)
	VPP_IMAGE_BASE=${BASE_REPO}:${BASE_TAG} BUILDENV_PRIVILEGED=1 build/buildenv.sh \
	bash -c "cd upf-plugin && $(MAKE) e2e"

generate-binapi: $(BUILDENV_DEPS)
	VPP_IMAGE_BASE=${BASE_REPO}:${BASE_TAG} BUILDENV_PRIVILEGED=1 build/buildenv.sh \
	bash -c "(cd upf-plugin && $(MAKE) genbinapi)"

debs: vpp-base
	cd upf-plugin && BUILD_TYPE=${BUILD_TYPE} VPP_IMAGE_BASE=${BASE_REPO}:${BASE_TAG} $(MAKE) debs

# Open VSCode attached to buildenv container
code: vpp-base
	VPP_IMAGE_BASE=${BASE_REPO}:${BASE_TAG} DEVENV_BG=1 BUILDENV_PRIVILEGED=1 build/buildenv.sh
	ENCNAME=`printf {\"containerName\":\"/vpp-build-$(BUILD_TYPE)-bg\"} | od -A n -t x1 | tr -d '[\n\t ]'`; \
	code --folder-uri "vscode-remote://attached-container+$${ENCNAME}/src"

# VPP include files differ from vpp-base source file, extract them to use language servers (like clangd)
.PHONY: extract-vpp-include
extract-vpp-include:
	@rm -rf .vpp-include.new
	mkdir .vpp-include.new
	BUILDENV_EXTRA_ARGS="--user $(shell id -u):$(shell id -g)" \
	VPP_IMAGE_BASE=${BASE_REPO}:${BASE_TAG} \
	build/buildenv.sh bash -c '\
		for pkg in libvppinfra-dev vpp-dev libnl-3-dev; do \
			dpkg -L $$pkg | grep "^/usr/include/" | xargs -I {} cp --parents {} /src/.vpp-include.new/ 2>/dev/null || true; \
		done'
	@rm -rf .vpp-include
	mv .vpp-include.new .vpp-include

.clangd: hack/clangd.template extract-vpp-include
	sed -e 's|{{PROJECT_ROOT}}|$(CURDIR)|g' \
	    hack/clangd.template > .clangd

.PHONY: help
help:
	@echo "Usage: make [target] [BUILD_TYPE=debug|release]"
	@echo ""
	@echo "Main Targets:"
	@echo "  vpp-base                 VPP with patches"
	@echo "  image                    VPP with UPF plugin"
	@echo ""
	@echo "Testing:"
	@echo "  test                     Run UPF plugin unit tests"
	@echo "  e2e                      Run UPF plugin E2E tests"
	@echo ""
	@echo "Development:"
	@echo "  initialize               Pull upstream VPP and apply patches"
	@echo "  buildenv                 Start build environment container"
	@echo "  code                     Open VSCode in build environment"
	@echo "  .clangd                  Generate configuration for clangd LSP server"
	@echo "  generate-binapi          Generate govpp binapi wrappers"
	@echo ""
	@echo "Charts:"
	@echo "  charts-test              Test Helm charts"
	@echo ""
	@echo "Other:"
	@echo "  debs                     "
	@echo ""
	@echo "Environment Variables:"
	@echo "  BUILD_TYPE               Build type: debug (default) or release"

