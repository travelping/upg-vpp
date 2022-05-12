# syntax = docker/dockerfile:experimental
# XXX: build-arg
ARG DEVBASE
ARG BASE
FROM ${DEVBASE} as build-stage

ARG BUILD_TYPE

ADD . /src

RUN BUILD_TYPE=${BUILD_TYPE} /src/hack/build-internal.sh package

FROM ${DEVBASE} as dev-stage

RUN --mount=target=/var/lib/apt/lists,type=cache,sharing=private \
    --mount=target=/var/cache/apt,type=cache,sharing=private \
    --mount=target=/build-root,source=/src/build-root,from=build-stage,type=bind \
    apt-get install --no-install-recommends -yy \
    /build-root/upf-plugin_*.deb \
    /build-root/upf-plugin-dev_*.deb && \
    apt-get clean && \
    mkdir -p /install && \
    cp -av /build-root/*.deb /install && \
    git config --global --add safe.directory /src

# this stage is used to copy out the debs
FROM scratch as artifacts

COPY --from=build-stage /src/build-root/*.deb .

# final image starts here
FROM ${BASE} as final-stage

RUN --mount=target=/var/lib/apt/lists,type=cache,sharing=private \
    --mount=target=/var/cache/apt,type=cache,sharing=private \
    --mount=target=/debs,source=/src/build-root,from=build-stage,type=bind \
    apt-get install --no-install-recommends -yy \
    /debs/upf-plugin_*.deb && \
    apt-get clean
