#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

cd "$(dirname "${BASH_SOURCE}")/.."

. vpp.spec

: ${UPG_BUILDENV:=default}
: ${K8S_ID:=${USER:-}}
: ${K8S_NAMESPACE:=default}
# FIXME: GRAB_ARTIFACTS is currently only supported in k8s mode
: ${GRAB_ARTIFACTS:=}
: ${UPG_BUILDENV_NODE:=}
: ${BUILD_TYPE:=debug}
: ${DEV_IMAGE:=${VPP_IMAGE_BASE}_dev_${BUILD_TYPE}}
: ${VPP_SRC:=}
: ${UPG_BUILDENV_EXTRA_DIR:=}

if [[ ${GITHUB_RUN_ID:-} ]]; then
  # avoid overlong pod names (must be <= 63 chars including the -0 suffix)
  K8S_ID=$(echo "${GITHUB_ACTOR}-${GITHUB_JOB}-${GITHUB_RUN_ID}" | md5sum | awk '{print substr($1,1,16)}')
  if [[ ${K8S_ID_SUFFIX:-} ]]; then
    K8S_ID="${K8S_ID}-${K8S_ID_SUFFIX}"
  fi
fi

K8S_ID=$(echo ${K8S_ID} | awk '{print tolower($0)}')

function docker_buildenv {
  priv=
  if [[ ${UPG_BUILDENV_PRIVILEGED:-} ]]; then
    priv="--privileged"
  fi
  # TODO: use compgen trick below
  opts=(-e LC_ALL=C.UTF-8 -e LANG=C.UTF-8)
  for var in $(compgen -v | grep '^E2E_') BUILD_TYPE; do
    opts+=(-e "${var}=${!var}")
  done
  if [[ -t 0 ]]; then
    opts+=(-it)
  fi

  if [[ ${UPG_BUILDENV_EXTRA_DIR:=} ]]; then
    opts+=(-v "${UPG_BUILDENV_EXTRA_DIR}:${UPG_BUILDENV_EXTRA_DIR}")
  fi

  if [[ ${VPP_SRC} ]]; then
    opts+=(-v "${VPP_SRC}:/vpp-src")
  fi

  docker run --rm --name vpp-build-${BUILD_TYPE} --shm-size 1024m \
         ${priv} \
         -v $PWD:/src:delegated -v $PWD/vpp-out:/vpp-out \
         "${opts[@]}" -w /src "${DEV_IMAGE}" "$@"
}

function k8s_statefulset_name {
  echo -n "upg-buildenv-${K8S_ID}-${BUILD_TYPE}"
}

function k8s_pod_name {
  echo -n "$(k8s_statefulset_name)-0"
}

function k8s_ensure_buildenv {
  local name=$(k8s_statefulset_name)
  node_selector=
  if [[ ${UPG_BUILDENV_NODE} ]]; then
    node_selector="nodeSelector: { kubernetes.io/hostname: ${UPG_BUILDENV_NODE} }"
  fi
  kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: ${name}
  namespace: ${K8S_NAMESPACE}
  labels:
    app: upg-build
spec:
  replicas: 1
  serviceName: ${name}
  selector:
    matchLabels:
      app-pod: ${name}
      upg-build: "1"
  template:
    metadata:
      labels:
        app-pod: ${name}
        upg-build: "1"
    spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: upg-build
                  operator: In
                  values:
                  - "1"
              topologyKey: kubernetes.io/hostname
            weight: 90
      ${node_selector}
      initContainers:
      - name: prepare
        image: busybox:stable
        command: ["/bin/mkdir", "-p", "/src"]
        volumeMounts:
        - name: data
          mountPath: /src
      containers:
      - name: buildenv
        image: ${DEV_IMAGE}
        imagePullPolicy: Always
        tty: true
        stdin: true
        securityContext:
          privileged: true
        command: ["/usr/bin/dumb-init", "/bin/bash", "-c", "sleep Infinity"]
        workingDir: /src
        env:
        - name: LC_ALL
          value: "C.UTF-8"
        - name: LANG
          value: "C.UTF-8"
        volumeMounts:
        - name: dshm
          mountPath: /dev/shm
        volumeMounts:
        - name: data
          mountPath: /src
      - name: rsyncd
        image: quay.io/travelping/rsyncd
        ports:
        - name: rsyncd
          containerPort: 873
        volumeMounts:
        - name: data
          mountPath: /data
      volumes:
      - name: data
        emptyDir: {}
      - name: dshm
        emptyDir:
          medium: Memory
---
apiVersion: v1
kind: Service
metadata:
  name: ${name}
  labels:
    app: upg-build
spec:
  ports:
  - name: rsync
    port: 873
    targetPort: 873
  selector:
    app: ${name}
EOF
  kubectl rollout status --timeout=5m statefulset -n "${K8S_NAMESPACE}" "${name}"
}

function k8s_cleanup {
  local name=$(k8s_statefulset_name)
  echo >&2 "Deleting buildenv statefulsets..."
  kubectl delete statefulset -n "${K8S_NAMESPACE}" --ignore-not-found -l app=upg-build
  echo >&2 "Deleting buildenv services..."
  kubectl delete service -n "${K8S_NAMESPACE}" --ignore-not-found "${name}"
}

function k8s_rsync {
  export RSYNC_CONNECT_PROG="kubectl exec -i -n '${K8S_NAMESPACE}' -c rsyncd '$(k8s_pod_name)' -- nc 127.0.0.1 873"
  rsync -av --compress-level=9 --delete --prune-empty-dirs --no-perms \
        --filter '- /artifacts/' \
        --filter '- __pycache__/' \
        --filter '- *.egg-info/' \
        --filter '- *.log' \
        --filter '- /build-root/' \
        ./ rsync://src@rsync/src/
}

function k8s_exec_i {
  kubectl exec -i -n "${K8S_NAMESPACE}" -c buildenv "$(k8s_pod_name)" -- "$@"
}

function k8s_exec {
  kubectl exec -n "${K8S_NAMESPACE}" -c buildenv "$(k8s_pod_name)" -- "$@"
}

function k8s_buildenv {
  case "${1:-}" in
    clean)
      k8s_cleanup
      return
      ;;
    *)
      k8s_ensure_buildenv
      k8s_rsync
      local cmd=()
      if [[ ! ${1:-} ]]; then
        cmd+=("-it" "--" "/bin/bash")
      else
        cmd+=("--")
        for var in $(compgen -v | grep '^E2E_') BUILD_TYPE; do
          if (( ${#cmd[@]} == 1 )); then
            cmd+=(/usr/bin/env)
          fi
          cmd+=("${var}=${!var}")
        done
        cmd+=("${@}")
      fi
      r=0
      kubectl exec -n "${K8S_NAMESPACE}" -c buildenv "$(k8s_pod_name)" "${cmd[@]}" || r=$?
      if [[ ${GRAB_ARTIFACTS} ]]; then
        if k8s_exec \
             /bin/bash -c '[[ -d /tmp/vpp-failed-unittests && $(ls -A /tmp/vpp-failed-unittests) ]]' >&/dev/null; then
          mkdir -p artifacts
          k8s_exec /bin/sh -c 'tar -C /tmp -ch vpp-failed-unittests && rm -rf /tmp/vpp*' |
            tar -C artifacts -xv
          # replace colons in filenames so GH Actions don't complain
          find artifacts/vpp-failed-unittests -name '*:*' -print0 |
            while IFS= read -d '' f; do mv "${f}" "${f//:/-}"; done
        fi
        if k8s_exec /bin/bash -c '[[ -d /src/artifacts && $(ls -A /src/artifacts) ]]' >& /dev/null; then
          mkdir -p artifacts
          k8s_exec /bin/sh -c 'tar -C /src -c artifacts && rm -rf /src/artifacts' | tar -C . -xv
        fi
      fi
      return $r
      ;;
    esac
}

case "${UPG_BUILDENV}" in
  default)
    exec "$@"
    ;;
  docker)
    docker_buildenv "$@"
    ;;
  k8s)
    k8s_buildenv "$@"
    ;;
  *)
    echo >&2 "Invalid UPG_BUILDENV: ${UPG_BUILDENV}"
    ;;
esac
