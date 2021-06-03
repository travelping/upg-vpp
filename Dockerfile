# syntax = docker/dockerfile:experimental
# the following is updated automatically by make update-build-image-tag
FROM quay.io/travelping/upg-build:10f03c8684150c9d0b492f050ca14d1e AS build-stage

ADD vpp /src/vpp
ADD upf /src/upf

RUN --mount=target=/src/vpp/build-root/.ccache,type=cache \
    make -C /src/vpp pkg-deb V=1 && \
    mkdir -p /out/debs && \
    mv /src/vpp/build-root/*.deb /out/debs && \
    tar -C /src/vpp -cvzf /out/testfiles.tar.gz build-root/install-vpp-native

# pseudo-image to extract artifacts using buildctl
FROM scratch as artifacts

COPY --from=build-stage /out .

# --- final image --------------------------------------------
FROM ubuntu:focal AS final-stage
WORKDIR /
ENV VPP_INSTALL_SKIP_SYSCTL=1
RUN --mount=target=/var/lib/apt/lists,type=cache,sharing=private \
    --mount=target=/var/cache/apt,type=cache,sharing=private \
    apt-get update && apt-get dist-upgrade -yy && \
    apt-get install --no-install-recommends -yy liblz4-tool tar gdb strace \
    libhyperscan5 libmbedcrypto3 libmbedtls12 libmbedx509-0 apt-utils \
    libpython2.7-minimal libpython2-stdlib libpython3-stdlib \
    python python-cffi python-cffi-backend python-ipaddress \
    python2-minimal python-ply python-pycparser python2.7 python2.7-minimal \
    python3 python3-minimal python3.6 python3-minimal \
    python3-cffi python3-cffi-backend libnuma1

# TODO: add more packages above that are VPP deps
RUN --mount=target=/var/lib/apt/lists,type=cache,sharing=private \
    --mount=target=/var/cache/apt,type=cache,sharing=private \
    --mount=target=/debs,source=/out/debs,from=build-stage,type=bind \
    apt-get install --no-install-recommends -yy \
    /debs/vpp_*.deb \
    /debs/vpp-dbg_*.deb \
    /debs/vpp-plugin-core_*.deb \
    /debs/vpp-plugin-dpdk*.deb \
    /debs/libvppinfra_*.deb \
    /debs/vpp-api-python_*.deb

ENTRYPOINT /usr/bin/vpp
