package traffic

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/sirupsen/logrus"

	"github.com/travelping/upg-vpp/test/e2e/network"
)

const (
	HTTP_DEFAULT_CHUNK_SIZE   = 100000
	HTTP_DEFAULT_READ_TIMEOUT = 5 * time.Second
)

type HTTPConfig struct {
	ServerIPs         []net.IP
	ServerPort        int
	ClientPort        int
	ChunkSize         int
	ChunkCount        int
	ChunkDelay        time.Duration
	ReadTimeout       time.Duration
	Retry             bool
	NoLinger          bool
	UseFakeHostname   bool
	SimultaneousCount int
	MaxRetries        int
	Persist           bool
}

var _ TrafficConfig = &HTTPConfig{}

func (cfg *HTTPConfig) AddServerIP(ip net.IP) {
	cfg.ServerIPs = append(cfg.ServerIPs, ip)
}

func (cfg *HTTPConfig) SetNoLinger(noLinger bool) { cfg.NoLinger = noLinger }

func (cfg *HTTPConfig) SetDefaults() {
	if cfg.ClientPort == 0 {
		cfg.ClientPort = 80
	}
	if cfg.ServerPort == 0 {
		cfg.ServerPort = cfg.ClientPort
	}
	if cfg.ChunkSize == 0 {
		cfg.ChunkSize = HTTP_DEFAULT_CHUNK_SIZE
	}
	if cfg.ChunkCount == 0 {
		if quickTest() {
			cfg.ChunkCount = 40
		} else {
			cfg.ChunkCount = 400
		}
	}
	if cfg.ChunkDelay == 0 {
		cfg.ChunkDelay = 50 * time.Millisecond
	}
	if cfg.SimultaneousCount == 0 {
		cfg.SimultaneousCount = 1
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 10
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = HTTP_DEFAULT_READ_TIMEOUT
	}
}

func (cfg *HTTPConfig) Server(rec TrafficRec) TrafficServer {
	return &HTTPServer{
		rec: rec,
		cfg: *cfg,
		log: logrus.WithField("trafficType", "http"),
	}
}

func (cfg *HTTPConfig) Client(rec TrafficRec) TrafficClient {
	return &HTTPClient{
		rec: rec,
		cfg: *cfg,
		log: logrus.WithField("trafficType", "http"),
	}
}

type HTTPServer struct {
	rec TrafficRec
	cfg HTTPConfig
	s   *http.Server
	log *logrus.Entry
}

var _ TrafficServer = &HTTPServer{}

func (hs *HTTPServer) Stop() {
	if hs.s != nil {
		hs.s.Close()
		hs.s = nil
	}
}

func (hs *HTTPServer) Start(ctx context.Context, ns *network.NetNS) error {
	if len(hs.cfg.ServerIPs) == 0 {
		return errors.New("no server IPs specified")
	}

	if hs.s != nil {
		return nil
	}

	chunk := make([]byte, hs.cfg.ChunkSize)
	if _, err := rand.Read(chunk); err != nil {
		return errors.Wrap(err, "rand read")
	}

	hs.s = &http.Server{
		BaseContext: func(net.Listener) context.Context { return ctx },
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			fileSize := hs.cfg.ChunkCount * hs.cfg.ChunkSize
			w.Header().Set("Content-Length", strconv.Itoa(fileSize))
			for i := 0; i < hs.cfg.ChunkCount; i++ {
				_, err := w.Write(chunk)
				if err != nil {
					// FIXME
					hs.log.WithError(err).Error("error serving the file")
					break
				}
				hs.rec.RecordStats(TrafficStats{ServerSent: len(chunk)})
				if hs.cfg.ChunkDelay > 0 {
					time.Sleep(hs.cfg.ChunkDelay)
				}
			}
		}),
	}

	listenAt := "0.0.0.0"
	if hs.cfg.ServerIPs[0].To4() == nil {
		listenAt = "[::]"
	}
	listenAddr := fmt.Sprintf("%s:%d", listenAt, hs.cfg.ServerPort)
	l, err := ns.ListenTCP(ctx, listenAddr)
	if err != nil {
		return errors.Wrap(err, "ListenTCP")
	}

	go func() {
		switch err := hs.s.Serve(l); {
		case err == http.ErrServerClosed:
			break
		case err != nil:
			hs.log.WithError(err).Warn("error serving http")
		}
	}()

	return nil
}

type HTTPClient struct {
	rec TrafficRec
	cfg HTTPConfig
	log *logrus.Entry
}

var _ TrafficClient = &HTTPClient{}

func (hc *HTTPClient) downloadURL(n int) string {
	portSuffix := ""
	if hc.cfg.ClientPort != 80 {
		portSuffix = fmt.Sprintf(":%d", hc.cfg.ClientPort)
	}
	serverIP := hc.cfg.ServerIPs[n%len(hc.cfg.ServerIPs)]
	var hostname string
	switch {
	case hc.cfg.UseFakeHostname:
		hostname = ipToFakeHostname(serverIP)
	case serverIP.To4() == nil:
		hostname = fmt.Sprintf("[%s]", serverIP)
	default:
		hostname = serverIP.String()
	}
	return fmt.Sprintf("http://%s%s/dummy", hostname, portSuffix)
}

func (hc *HTTPClient) download(ctx context.Context, ns *network.NetNS, url string) error {
	log := hc.log.WithField("url", url)
	c := httpClient(ns, hc.cfg.NoLinger)
	chunk := make([]byte, hc.cfg.ChunkSize)
	retry := false
	retrySucceeded := false
	for i := 0; hc.cfg.Persist || (i < hc.cfg.MaxRetries && !retrySucceeded); i++ {
		// FIXME: this needs to be refactored
		cont, err := func() (bool, error) {
			childCtx, childCancel := context.WithCancel(ctx)
			timer := time.AfterFunc(hc.cfg.ReadTimeout, func() {
				childCancel()
			})
			defer childCancel()
			defer timer.Stop()
			req, err := http.NewRequestWithContext(childCtx, "GET", url, nil)
			resp, err := c.Do(req)
			if err != nil {
				if hc.cfg.Retry && ctx.Err() == nil {
					log.WithError(err).Trace("HTTP GET failed")
					retry = true
					return true, nil
				}
				if hc.cfg.Persist {
					// context cancelled
					return false, nil
				}
				return false, errors.Wrap(err, "HTTP GET")
			}
			defer func() {
				resp.Body.Close()
				c.CloseIdleConnections()
			}()

			for {
				timer.Reset(hc.cfg.ReadTimeout)
				n, err := resp.Body.Read(chunk)
				if retry && n > 0 {
					retrySucceeded = true
				}
				hc.rec.RecordStats(TrafficStats{ClientReceived: n})
				if err == io.EOF {
					return false, nil
				}
				if err != nil {
					if hc.cfg.Retry && ctx.Err() == nil {
						log.WithError(err).Trace("HTTP GET failed")
						retry = true
						return true, nil
					}
					if hc.cfg.Persist {
						// context cancelled
						return false, nil
					}
					return false, errors.Wrap(err, "error reading HTTP response")
				}
			}
		}()
		if err != nil {
			return err
		}
		if !cont {
			break
		}
	}

	// the point is that if the connection fails, it must be possible to retry afterwards
	if retry && !retrySucceeded && !hc.cfg.Persist {
		return errors.New("retries were attempted, but none succeeded")
	}

	return nil
}

func (hc *HTTPClient) Run(ctx context.Context, ns *network.NetNS) error {
	if len(hc.cfg.ServerIPs) == 0 {
		return errors.New("no server IPs specified")
	}

	ts := time.Now()

	hc.log.WithField("numConns", hc.cfg.SimultaneousCount).Info("downloading")
	var wg sync.WaitGroup
	wg.Add(hc.cfg.SimultaneousCount)
	for i := 0; i < hc.cfg.SimultaneousCount; i++ {
		go func(n int) {
			defer wg.Done()
			url := hc.downloadURL(n)
			if err := hc.download(ctx, ns, url); err != nil {
				hc.rec.RecordError("download error: %v", err)
			}
		}(i)
	}
	wg.Wait()

	elapsed := time.Since(ts)
	rcvBytes := hc.rec.Stats().ClientReceived
	hc.log.WithFields(logrus.Fields{
		"total":   rcvBytes,
		"elapsed": elapsed,
		"Mbps":    float64(rcvBytes) * 8.0 * float64(time.Second) / (1000000. * float64(elapsed)),
	}).Info("download finished")

	return nil
}
