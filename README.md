User Plane Gateway (UPG) based on VPP
=====================================
[![CI](https://github.com/travelping/upg-vpp/actions/workflows/main.yaml/badge.svg?branch=master)](https://github.com/travelping/upg-vpp/actions/workflows/main.yaml)

UPG implements a GTP-U user plane based on [3GPP TS 23.214][TS23214]
and [3GPP TS 29.244][TS29244] Release 15. It is implemented as an
out-of-tree plugin for [FD.io VPP][VPP].

The possible uses for UPG are:
* User Plane Function (UPF) in 5G networks
* Packet Data Network Gateway User plane (PGW-U)
* Traffic Detection Function User plane (TDF-U)

Current State
-------------

UPG is used in production in conjunction with [erGW][erGW] as GGSN/PGW
in multiple installation in several telecom operators (Tier 1 and
smaller).

For the list of known issues, see [KNOWN_ISSUES document](KNOWN_ISSUES.md).

Working features
----------------

* PFCP protocol
  * en/decoding of most IEs
  * heartbeat
  * node related messages
  * session related messages
* Uplink and Downlink Packet Detection Rules (PDR) and
  Forward Action Rules (FAR) -- (some parts)
* IPv4 -- inner and outer
* IPv6 -- inner and outer
* Usage Reporting Rules (URR)
* PFCP Session Reports
* Linked Usage Reports

No yet working
--------------

* Buffer Action Rules (BAR)
* QoS Enforcement Rule (QER)

Limitations
-----------

* FAR action with destination LI are not implemented
* Ethernet bearer support


Development setup
-----------------

Design rationale for the development environment is this:

* provide an easily reproducible development and build environment
  usable both on CI and locally
* provide quick commands for common tasks
* simplify bisecting against upstream VPP
* discourage downstream VPP changes, as we should make effort to
  upstream them

Relevant parts of the source tree layout:
* `hack/` contains helper scripts most of which are wrapped in `make`
  commands
* `Makefile` provides user interface for the environment
* `upf/` contains the source code of the plugin<sup>[1](#footnote-1)</sup>
* `upf/test/` contains the integration tests<sup>[1](#footnote-1)</sup>
* `vpp.spec` contains the info on VPP-base repo, branch and commit to use

There's a simple dockerized environment wrapped in 'make'
commands.

The "build image" which is used for the devenv is tagged with a hash
of `Dockerfile.build` as well as VPP's external dependencies.

The following `make` commands are supported:

* `make image` builds UPG Docker image
* `make test` build VPP and run UPG integration tests. The compilation
  results are retained under `vpp/`
* `make retest` run UPG integration tests without building VPP. These
  can be run under `make test` to re-run the tests quickly if there
  were no UPG / VPP code changes
* `make ensure-build-image` checks if the build image exists or can be
  pulled and builds it otherwise
* `make update-build-image-tag` updates the build image tag in
  the Dockerfiles according to the hash calculated
  from `Dockerfile.build` and VPP external dependencies
* `make install-hooks` installs git hooks in the repo which prevent
  the user from making commits that contain `ZZZZZ:` substring. This
  is handy for debug print like `clib_warning("ZZZZZ: i %d", i);`
* `make update-vpp` re-clones VPP into `vpp/` directory
* `make buildenv` runs an interactive shell inside the build
  environment with UPG and VPP sources mounted into the container
* `make e2e` build UPG and run E2E tests for it. For more information,
  see [E2E test documentation](test/e2e/README.md)
* `make checkstyle` performs style checks on the source code

Commands for building images and running tests default to debug builds.
To do release build instead, pass `BUILD_TYPE=release` to `make`:

```sh
make e2e BUILD_TYPE=release
```

If docker is used, one should set the following environment variable
to enable wrapping the internally run commands in a docker container:

```sh
export UPG_BUILDENV=docker
```

It is also possible to use a k8s cluster to run the build container in a pod:
```
export UPG_BUILDENV=k8s
# optional: specify the node to run the build pod
export UPG_BUILDENV_NODE=somenode
```
In this case, the buildenv is run as statefulset inside the cluster.
It can be removed using
```sh
hack/buildenv.sh clean
```

CI and releases
---------------

The CI for UPG-VPP is based on [GitHub Actions][GHACTIONS]. Currently,
the CI only runs for pushes to branches in the repository itself.
The jobs include:
- `prepare`: make sure build image is available for the commit
- `build` (debug + release): build the docker images and binaries / packages
- `checkstyle`: check for style errors in the code
- `test`: unit and e2e tests for release and debug builds
- `conclude`: intermediate job used for sync by the release workflow
- `slack`: internal notification job

The images built per-commit expire within 7 days.

When a tag is pushed, the `release` workflow is also run for it,
re-tagging the images built as part of normal build process
(preserving the old tags too). In case if the tag doesn't have `test`
substring in it, it is also published as a release. The release notes
list the PRs with the following tags:
- `feature`, `enhancement`: features
- `fix`: fixes
- `test`: tests

The releases for tags that contain `pre` substring are marked as
pre-releases.

[VPP]: https://fd.io
[erGW]: https://github.com/travelping/ergw
[TS23214]: http://www.3gpp.org/ftp/Specs/html-info/23214.htm
[TS29244]: http://www.3gpp.org/ftp/Specs/html-info/29244.htm
[VPPBUILD]: https://wiki.fd.io/view/VPP/Pulling,_Building,_Running,_Hacking_and_Pushing_VPP_Code#Building
[GHACTIONS]: https://github.com/features/actions

<a name="footnote-1">1</a>: Historically, the project was named simply "UPF". There may be more UPF->UPG renames later
