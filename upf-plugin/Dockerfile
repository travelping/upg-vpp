# syntax = docker/dockerfile:experimental
# XXX: build-arg
ARG DEVBASE
ARG BASE
FROM ${DEVBASE} as build-stage

ARG BUILD_TYPE
ARG VER

ADD . /src/upf-plugin

RUN --mount=target=/ccache,type=cache \
    PATH="/usr/lib/ccache:$PATH" && \
    VER=${VER} BUILD_TYPE=${BUILD_TYPE} /src/upf-plugin/hack/build-internal.sh package && \
    ccache -s

FROM ${DEVBASE} as dev-stage

RUN --mount=target=/var/lib/apt,type=cache,sharing=locked \
    --mount=target=/var/cache/apt,type=cache,sharing=locked \
    --mount=target=/build-root,source=/src/upf-plugin/build-root,from=build-stage,type=bind \
    apt-get install --no-install-recommends -yy \
        /build-root/upf-plugin_*.deb \
        /build-root/upf-plugin-dev_*.deb && \
    mkdir -p /install && \
    cp -av /build-root/*.deb /install && \
    git config --global --add safe.directory /src/upf-plugin

# this stage is used to copy out the debs
FROM scratch as artifacts

COPY --from=build-stage /src/upf-plugin/build-root/*.deb .

# final image starts here
FROM ${BASE} as final-stage

RUN --mount=target=/var/lib/apt,type=cache,sharing=locked \
    --mount=target=/var/cache/apt,type=cache,sharing=locked \
    --mount=target=/debs,source=/src/upf-plugin/build-root,from=build-stage,type=bind \
    apt-get install --no-install-recommends -yy \
    /debs/upf-plugin_*.deb
