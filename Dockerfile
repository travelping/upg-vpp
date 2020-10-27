# syntax = docker/dockerfile:experimental
# the following is updated automatically by make update-build-image-tag
FROM quay.io/travelping/upg-build:3ba60fbb1e5584fac28ff8351b37c8e6 AS build-stage

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
FROM ubuntu:bionic AS final-stage
WORKDIR /
RUN --mount=target=/var/lib/apt/lists,type=cache,sharing=private \
    --mount=target=/var/cache/apt,type=cache,sharing=private \
    apt-get update && apt-get dist-upgrade -yy && \
    apt-get install --no-install-recommends -yy liblz4-tool tar \
    libhyperscan4 libmbedcrypto1 libmbedtls10 libmbedx509-0 libpython-stdlib \
    libpython2.7-minimal libpython2.7-stdlib libpython3-stdlib \
    python python-cffi python-cffi-backend python-ipaddress \
    python-minimal python-ply python-pycparser python2.7 python2.7-minimal \
    python3 python3-minimal python3.6 python3.6-minimal

# TODO: add more packages above that are VPP deps
RUN --mount=target=/var/lib/apt/lists,type=cache,sharing=private \
    --mount=target=/var/cache/apt,type=cache,sharing=private \
    --mount=target=/debs,source=/out/debs,from=build-stage,type=bind \
    apt-get install --no-install-recommends -yy \
    /debs/vpp_*.deb \
    /debs/vpp-dbg_*.deb \
    /debs/vpp-plugin-core_*.deb \
    /debs/libvppinfra_*.deb \
    /debs/vpp-api-python_*.deb

ENTRYPOINT /usr/bin/vpp
