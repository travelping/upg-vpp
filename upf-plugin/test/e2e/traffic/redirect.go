// redirect.go - 3GPP TS 29.244 GTP-U UP plug-in
//
// Copyright (c) 2021 Travelping GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package traffic

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/sirupsen/logrus"

	"github.com/travelping/upg-vpp/test/e2e/network"
)

const (
	REDIRECT_READ_TIMEOUT = 5 * time.Second
	REDIRECT_READ_RETRIES = 5
)

type RedirectConfig struct {
	Count                  int
	ServerIP               net.IP
	ClientPort             int
	Retry                  bool
	NoLinger               bool
	Delay                  time.Duration
	RedirectLocationSubstr string
	RedirectResponseSubstr string
}

var _ TrafficConfig = &RedirectConfig{}

func (cfg *RedirectConfig) AddServerIP(ip net.IP) {
	if cfg.ServerIP != nil {
		panic("only single ServerIP is supported")
	}
	cfg.ServerIP = ip
}

func (cfg *RedirectConfig) HasServerIP() bool {
	return cfg.ServerIP != nil
}

func (cfg *RedirectConfig) SetNoLinger(noLinger bool) { cfg.NoLinger = noLinger }

func (cfg *RedirectConfig) SetDefaults() {
	if cfg.ClientPort == 0 {
		cfg.ClientPort = 80
	}
	if cfg.Count == 0 {
		cfg.Count = 40
	}
	// FIXME: make it possible to specify zero delay
	if cfg.Delay == 0 {
		cfg.Delay = 300 * time.Millisecond
	}
}

func (cfg *RedirectConfig) Server(rec TrafficRec) TrafficServer { return nullServer }

func (cfg *RedirectConfig) Client(rec TrafficRec) TrafficClient {
	return &RedirectClient{
		rec: rec,
		cfg: cfg,
		log: logrus.WithField("trafficType", "redirect"),
	}
}

type RedirectClient struct {
	rec TrafficRec
	cfg *RedirectConfig
	log *logrus.Entry
}

var _ TrafficClient = &RedirectClient{}

func (rc *RedirectClient) downloadURL() string {
	portSuffix := ""
	if rc.cfg.ClientPort != 80 {
		portSuffix = fmt.Sprintf(":%d", rc.cfg.ClientPort)
	}
	if rc.cfg.ServerIP.To4() == nil {
		return fmt.Sprintf("http://[%s]%s/dummy", rc.cfg.ServerIP, portSuffix)
	}
	return fmt.Sprintf("http://%s%s/dummy", rc.cfg.ServerIP, portSuffix)
}

func (rc *RedirectClient) checkRedirectOnce(ctx context.Context, ns *network.NetNS) (mayRetry bool, err error) {
	url := rc.downloadURL()
	log := rc.log.WithField("url", url)
	log.Info("accessing URL expecting redirect")
	c := httpClient(ns, "", rc.cfg.NoLinger, REDIRECT_READ_TIMEOUT/REDIRECT_READ_RETRIES)
	// https://stackoverflow.com/a/38150816
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	ctx, cancel := context.WithCancel(ctx)
	timer := time.AfterFunc(REDIRECT_READ_TIMEOUT, func() { cancel() })
	defer timer.Stop()

	var bs []byte
	var resp *http.Response
	defer func() {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		c.CloseIdleConnections()
	}()

	for retry := 0; retry < REDIRECT_READ_RETRIES; retry++ {
		var req *http.Request
		req, err = http.NewRequestWithContext(ctx, "GET", url, nil)

		if resp != nil && resp.Body != nil {
			// close previous response when retrying
			resp.Body.Close()
		}

		resp, err = c.Do(req)
		if err != nil {
			if isConnTimeout(err) || isConnReset(err) {
				continue
			} else {
				break
			}
		}

		bs, err = ioutil.ReadAll(resp.Body)
		if err != nil && isConnReset(err) {
			continue
		} else {
			break
		}
	}
	if err != nil {
		return true, errors.Wrap(err, "HTTP GET")
	}

	if rc.cfg.RedirectResponseSubstr != "" &&
		!strings.Contains(string(bs), rc.cfg.RedirectResponseSubstr) {
		return false, errors.Errorf("bad redirect response body:\n%s", bs)
	}

	loc, err := resp.Location()
	if err != nil {
		if errors.Is(err, http.ErrNoLocation) {
			return false, errors.New("no location in redirect response")
		}
		return false, errors.Wrap(err, "error getting response location")
	}

	log.WithField("location", loc).Info("got redirect")

	if rc.cfg.RedirectLocationSubstr != "" &&
		!strings.Contains(loc.String(), rc.cfg.RedirectLocationSubstr) {
		return false, errors.Errorf("bad redirect location %q", loc)
	}

	return true, nil
}

func (rc *RedirectClient) Run(ctx context.Context, ns *network.NetNS) error {
	retry := false
	retrySucceeded := false

	for i := 0; i < rc.cfg.Count; i++ {
		mayRetry, err := rc.checkRedirectOnce(ctx, ns)
		switch {
		case err == nil && retry:
			retrySucceeded = true
			fallthrough
		case err == nil:
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(rc.cfg.Delay):
			}
			continue
		case !rc.cfg.Retry || !mayRetry:
			return err
		default:
			rc.log.WithError(err).Warn("retryable checkRedirect error")
			retry = true
		}
	}

	if retry && !retrySucceeded {
		return errors.New("retries were attempted, but none succeeded")
	}

	return nil
}
