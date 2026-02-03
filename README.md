User Plane Gateway (UPG) based on VPP
=====================================
[![CI](https://github.com/travelping/upg-vpp/actions/workflows/ci.yaml/badge.svg?branch=master)](https://github.com/travelping/upg-vpp/actions/workflows/ci.yaml)

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
in multiple installations in several telecom operators (Tier 1 and
smaller).

For the list of known issues, see [KNOWN_ISSUES document](upf-plugin/KNOWN_ISSUES.md).

Working features
----------------

* PFCP protocol
  * en-/decoding of most IEs
  * heartbeat
  * node-related messages
  * session-related messages
* Uplink and Downlink Packet Detection Rules (PDR) and
  Forward Action Rules (FAR) -- (some parts)
* IPv4 -- inner and outer
* IPv6 -- inner and outer
* Usage Reporting Rules (URR)
* PFCP Session Reports
* Linked Usage Reports

Not yet working
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
* discourage downstream VPP changes, as we should make an effort to
  upstream them

Relevant parts of the source tree layout:
* `build/` contains helper scripts, most of which are wrapped in `make`
  commands
* `Makefile` provides a user interface for the environment
* `upf-plugin/upf/` contains the source code of the plugin<sup>[1](#footnote-1)</sup>
* `upf-plugin/upf/test/` contains the integration tests<sup>[1](#footnote-1)</sup>
* `upf-plugin/vpp-base/` contains the [base VPP repository](https://github.com/travelping/fpp-vpp)

DEB packages containing UPG can be built using:

```bash
make debs
```

After a successful build, you can find the packages in the  `.out` directory.

To build a Docker image that contains UPG along with the base VPP, run:

```bash
make image
```

You can run integration tests with:

```bash
make test
```

To run E2E tests, use:

```bash
make e2e
```

Commands for building an image and running tests default to debug builds.
To do a release build instead, pass `BUILD_TYPE=release` to `make`:

```sh
make e2e BUILD_TYPE=release
```

There's a simple dockerized environment wrapped in 'make'
commands. To enter it, run:

```bash
make buildenv
```

The following `make` commands are supported in a dockerized environment:

* `make install` rebuilds UPG and installs the resulting binaries into the
  current environment.
* `make test` builds VPP and runs UPG integration tests. The compilation
  results are retained under `vpp/`.
* `make retest` runs UPG integration tests without building VPP. These
  can be run under `make test` to rerun the tests quickly if there
  were no UPG / VPP code changes.
* `make e2e` builds UPG and runs E2E tests for it. For more information,
  see [E2E test documentation](upf-plugin/test/e2e/README.md).
* `make retest-e2e` runs E2E tests without building VPP.
* `make checkstyle` performs style checks on the source code.
* `make genbinapi` generates the govpp binary API used in E2E tests.

CI and releases
---------------

The CI for UPG-VPP is based on [GitHub Actions][GHACTIONS]. Currently,
the CI only runs for pushes to branches in the repository itself.
The jobs include:
- `prepare`: make sure the build image is available for the commit
- `build` (debug + release): build Docker images and binaries/packages
- `checkstyle`: check for style errors in the code
- `test`: unit and e2e tests for release and debug builds
- `conclude`: intermediate job used for sync by the release workflow
- `slack`: internal notification job

The images built per-commit expire within 7 days.

When a tag is pushed, the `release` workflow is also run for it,
re-tagging the images built as part of the normal build process
(preserving the old tags too). The release notes
list the PRs with the following tags:
- `feature`, `enhancement`: features
- `fix`: fixes
- `test`: tests

[VPP]: https://fd.io
[erGW]: https://github.com/travelping/ergw
[TS23214]: http://www.3gpp.org/ftp/Specs/html-info/23214.htm
[TS29244]: http://www.3gpp.org/ftp/Specs/html-info/29244.htm
[VPPBUILD]: https://wiki.fd.io/view/VPP/Pulling,_Building,_Running,_Hacking_and_Pushing_VPP_Code#Building
[GHACTIONS]: https://github.com/features/actions

<a name="footnote-1">1</a>: Historically, the project was named simply "UPF". There may be more UPF->UPG renames later

VS Code
---------------

It is possible to attach to a running buildenv container with VS Code to get full IntelliSense.

To do that, run `make code`.

*Note:* This command leaves the buildenv running in the background.

After attaching for the first time, some VS Code plugins may not be enabled.
To fix that, open: `F1 -> "Dev Containers: Open Named Container Configuration File"`
And specify what plugins you'd like loaded at start.

Here are some nice plugins to work with this repo:
```
{
	"workspaceFolder": "/src",
	"extensions": [
		"eamodio.gitlens",
		"EditorConfig.EditorConfig",
		"golang.go",
		"ms-azuretools.vscode-docker",
		"ms-vscode.cmake-tools",
		"ms-vscode.cpptools",
		"ms-vscode.cpptools-extension-pack",
		"ms-vscode.cpptools-themes",
		"ms-vscode.makefile-tools",
		"llvm-vs-code-extensions.vscode-clangd",
		"xaver.clang-format",
		"twxs.cmake",
	],
}
```
