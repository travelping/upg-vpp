package framework

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net"
	"os/exec"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"github.com/travelping/upg-vpp/test/e2e/network"
)

type IPerf3 struct {
	ServerMode bool
	Duration   time.Duration
	NS         *network.NetNS
	ServerIP   net.IP
	Reverse    bool
	cmd        *exec.Cmd
}

type IPerfResult struct {
	Error string         `json:"error"`
	End   IPerfResultEnd `json:"end"`
}

type IPerfResultEnd struct {
	SumSent     IPerfResultByteStats `json:"sum_sent"`
	SumReceived IPerfResultByteStats `json:"sum_received"`
}

type IPerfResultByteStats struct {
	Bytes uint32 `json:"bytes"`
}

func (ipf *IPerf3) Start() error {
	args := []string{
		"--net=" + ipf.NS.Path(),
		"iperf3",
		"-J", // JSON output
	}

	if ipf.ServerMode {
		args = append(args, "-s", "-1") // -1 means one-off
	} else {
		args = append(
			args, "-c", ipf.ServerIP.String(),
			"-t", strconv.Itoa(int(math.Round(ipf.Duration.Seconds()))))
	}

	if ipf.Reverse {
		args = append(args, "-R")
	}

	ipf.cmd = exec.Command("nsenter", args...)
	ipf.cmd.Stdout = &bytes.Buffer{}
	ipf.cmd.Stderr = &bytes.Buffer{}
	if err := ipf.cmd.Start(); err != nil {
		return errors.Wrap(err, "error starting iperf3")
	}

	return nil
}

func (ipf *IPerf3) Kill() {
	if !ipf.cmd.ProcessState.Exited() {
		ipf.cmd.Process.Kill()
	}
}

func (ipf *IPerf3) Wait(ctx context.Context) (*IPerfResult, error) {
	doneCh := make(chan struct{})
	defer close(doneCh)
	go func() {
		select {
		case <-ctx.Done():
			ipf.Kill()
		case <-doneCh:
		}
	}()

	// In JSON mode (-J), iperf3 doesn't print anything on stderr,
	// but there can also be an error message from nsenter
	runErr := ipf.cmd.Wait()
	if runErr != nil {
		errMsg := ipf.cmd.Stderr.(*bytes.Buffer).Bytes()
		if len(errMsg) != 0 {
			return nil, errors.Wrapf(runErr, "nsenter/iperf3 failed:\n%s", errMsg)
		}
		// no error message from stderr, need to parse stdout below
	}

	out := ipf.cmd.Stdout.(*bytes.Buffer)
	var r IPerfResult
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		return nil, errors.Wrapf(err, "error unmarshalling iperf3 result:\n%s", out.Bytes())
	}

	if runErr != nil {
		return nil, errors.Wrapf(runErr, "error running iperf3: %s", r.Error)
	}

	return &r, nil
}
