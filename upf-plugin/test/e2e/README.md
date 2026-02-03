# UPG End-to-End tests

UPG End-to-End (E2E) tests run VPP with UPG plugin as a subprocess in a
separate network namespace, making it pass traffic between other
network namespaces while trying to break it in different ways.

The tests are written in Go to provide acceptable performance for
timing-sensitive tests while still being easy enough to maintain.

The following packages need to be present in the system
(Ubuntu/Debian) to run E2E tests, unless dockerized environment is
used:

* gdb
* golang-go (preferably 1.15, e.g. from [golang-backports](https://launchpad.net/~longsleep/+archive/ubuntu/golang-backports))
* libpcap-dev

The tests are invoked from the top project directory using either
`make e2e-debug` or `make e2e-release` commands.

The make commands accept following variables:

* `E2E_RETEST`: if non-empty, don't build UPG before starting the tests
* `E2E_VERBOSE`: if non-empty, enable verbose output for the tests
* `E2E_PARALLEL`: if non-empty, run tests in parallel
* `E2E_PARALLEL_NODES`: specify the number of parallel processes (nodes) for parallel testing
* `E2E_FOCUS`: an optional regexp for selecting a subset of tests to run by name
* `E2E_SKIP`: an optional regexp for selecting a subset of tests to skip by name
* `E2E_ARTIFACTS_DIR`: target directory for test artifacts (note, must
  start with /src in case of Docker env, where `/src` corresponds to
  the project root)
* `E2E_JUNIT_DIR`: target directory for test reports in JUnit XML format
* `E2E_QUICK`: do shorter tests (pass less traffic)
* `E2E_FLAKE_ATTEMPTS`: retry failed tests specified amount of times
* `E2E_TRACE`: enable VPP trace
* `E2E_DISPATCH_TRACE`: store the VPP dispatch trace as `dispatch-trace.pcap` in the test dir
* `E2E_PAUSE_ON_ERROR`: pause on error for interactive debugging
* `E2E_MULTICORE`: run tests with a single worker core enabled
* `E2E_KEEP_ALL_ARTIFACTS`: store artifacts even for successful tests
* `E2E_GDBSERVER`: run VPP under gdbserver. After VPP is started, you need to copy-paste
  the `gdb ...` command from test output into your console and type `cont` there (and press Enter)
  to continue running the test
* `E2E_FAIL_FAST`: stop running tests after the first failure

An example with multiple flags:

```sh
make e2e-debug \
    E2E_QUICK=1 \
    E2E_ARTIFACTS_DIR=/src/artifacts \
    E2E_JUNIT_DIR=/src/junit \
    E2E_PARALLEL=y \
    E2E_PARALLEL_NODES=4 \
    E2E_FOCUS=PGW
```
