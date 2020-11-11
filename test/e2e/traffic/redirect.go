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

func (cfg *RedirectConfig) SetServerIP(ip net.IP)     { cfg.ServerIP = ip }
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
	c := httpClient(ns, rc.cfg.NoLinger)
	// https://stackoverflow.com/a/38150816
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	ctx, cancel := context.WithCancel(ctx)
	timer := time.AfterFunc(READ_TIMEOUT, func() { cancel() })
	defer timer.Stop()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := c.Do(req)
	if err != nil {
		return true, errors.Wrap(err, "HTTP GET")
	}
	defer func() {
		resp.Body.Close()
		c.CloseIdleConnections()
	}()

	bs, err := ioutil.ReadAll(resp.Body)
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
