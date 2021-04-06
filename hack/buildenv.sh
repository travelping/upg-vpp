#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

: ${UPG_BUILDENV:=default}
: ${K8S_ID:=${USER:-}}
: ${K8S_NAMESPACE:=default}
# FIXME: GRAB_ARTIFACTS is currently only supported in k8s mode
: ${GRAB_ARTIFACTS:=}

if [[ ${GITHUB_RUN_ID:-} ]]; then
  K8S_ID="${GITHUB_ACTOR}-${GITHUB_JOB}-${GITHUB_RUN_ID}"
  if [[ ${K8S_ID_SUFFIX:-} ]]; then
    K8S_ID="${K8S_ID}-${K8S_ID_SUFFIX}"
  fi
fi

cd "$(dirname "${BASH_SOURCE}")/.."

function docker_buildenv {
  priv=
  if [[ ${UPG_BUILDENV_PRIVILEGED:-} ]]; then
    priv="--privileged"
  fi
  . hack/build-image-name.sh
  # TODO: use compgen trick below
  docker run -it --rm --name vpp-build --shm-size 1024m \
         ${priv} \
         -v $PWD:/src:delegated \
         -v $PWD/vpp-out:/vpp-out \
         -e LC_ALL=C.UTF-8 \
         -e LANG=C.UTF-8 \
         -e E2E_RETEST="${E2E_RETEST:=}" \
         -e E2E_VERBOSE="${E2E_VERBOSE:-}" \
         -e E2E_PARALLEL="${E2E_PARALLEL:-}" \
         -e E2E_PARALLEL_NODES="${E2E_PARALLEL_NODES:-}" \
         -e E2E_FOCUS="${E2E_FOCUS:-}" \
         -e E2E_SKIP="${E2E_SKIP:-}" \
         -e E2E_TARGET="${E2E_TARGET:-}" \
         -e E2E_ARTIFACTS_DIR="${E2E_ARTIFACTS_DIR:-}" \
         -e E2E_JUNIT_DIR="${E2E_JUNIT_DIR:-}" \
         -e E2E_QUICK="${E2E_QUICK:-}" \
         -e E2E_FLAKE_ATTEMPTS="${E2E_FLAKE_ATTEMPTS:-}" \
         -e E2E_TRACE="${E2E_TRACE:-}" \
         -e E2E_DISPATCH_TRACE="${E2E_DISPATCH_TRACE:-}" \
         -e E2E_PAUSE_ON_ERROR="${E2E_PAUSE_ON_ERROR:-}" \
         -e E2E_MULTICORE="${E2E_MULTICORE:-}" \
         -w /src/vpp \
         "${build_image}" \
         "$@"
}

function k8s_statefulset_name {
  echo -n "upg-buildenv-${K8S_ID}"
}

function k8s_pod_name {
  echo -n "$(k8s_statefulset_name)-0"
}

function k8s_ensure_buildenv {
  local name=$(k8s_statefulset_name)
  kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: ${name}
  namespace: ${K8S_NAMESPACE}
spec:
  replicas: 1
  serviceName: ${name}
  selector:
    matchLabels:
      app: ${name}
      upg-build: "1"
  template:
    metadata:
      labels:
        app: ${name}
        upg-build: "1"
    spec:
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: upg-build
                operator: In
                values:
                - "1"
            topologyKey: kubernetes.io/hostname
      initContainers:
      - name: prepare
        image: busybox:stable
        command: ["/bin/mkdir", "-p", "/src/vpp"]
        volumeMounts:
        - name: data
          mountPath: /src
      containers:
      - name: buildenv
        image: ${build_image}
        tty: true
        stdin: true
        securityContext:
          privileged: true
        command: ["/usr/bin/dumb-init", "/bin/bash", "-c", "sleep Infinity"]
        workingDir: /src/vpp
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
spec:
  ports:
  - name: rsync
    port: 873
    targetPort: 873
  selector:
    app: ${name}
EOF
  kubectl rollout status statefulset -n "${K8S_NAMESPACE}" "${name}"
}

function k8s_cleanup {
  local name=$(k8s_statefulset_name)
  kubectl delete statefulset -n "${K8S_NAMESPACE}" --ignore-not-found "${name}"
  kubectl delete service -n "${K8S_NAMESPACE}" --ignore-not-found "${name}"
}

function k8s_rsync {
  export RSYNC_CONNECT_PROG="kubectl exec -i -n '${K8S_NAMESPACE}' -c rsyncd '$(k8s_pod_name)' -- nc 127.0.0.1 873"
  rsync -av --compress-level=9 --delete --prune-empty-dirs --no-perms \
        --filter '- /vpp/build-root/.ccache/' \
        --filter '- /vpp/build-root/build-test/' \
        --filter '- /vpp/build-root/build-vpp_debug-native/' \
        --filter '- /vpp/build-root/install-vpp_debug-native/' \
        --filter '- /vpp/build-root/build-vpp-native/' \
        --filter '- /vpp/build-root/install-vpp-native/' \
        --filter '- /artifacts/' \
        --filter '- __pycache__/' \
        --filter '- *.egg-info/' \
        --filter '- *.log' \
        ./ rsync://src@rsync/src/
}

function k8s_exec_i {
  kubectl exec -i -n "${K8S_NAMESPACE}" -c buildenv "$(k8s_pod_name)" -- "$@"
}

function k8s_exec {
  kubectl exec -n "${K8S_NAMESPACE}" -c buildenv "$(k8s_pod_name)" -- "$@"
}

function k8s_buildenv {
  . hack/build-image-name.sh
  case "${1:-}" in
    clean)
      k8s_cleanup
      return
      ;;
    inject-testfiles)
      k8s_ensure_buildenv
      k8s_rsync
      local test_archive="${2:-}"
      k8s_exec_i tar -C /src/vpp -xvz <"${test_archive}"
      ;;
    *)
      k8s_ensure_buildenv
      k8s_rsync
      local cmd=()
      if [[ ! ${1:-} ]]; then
        cmd+=("-it" "--" "/bin/bash")
      else
        cmd+=("--")
        for var in $(compgen -v); do
          if [[ ${var} =~ ^E2E_ ]]; then
            if (( ${#cmd[@]} == 1 )); then
              cmd+=(/usr/bin/env)
            fi
            cmd+=("${var}=${!var}")
          fi
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

if [[ ! ${SKIP_VPP_SOURCE_CHECK:-} && ! -e vpp/Makefile ]]; then
  echo >&2 "Please run 'make update-vpp'"
  exit 1
fi

case "${UPG_BUILDENV}" in
  default)
    cd vpp
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

# TBD: exclude build dirs!!!
