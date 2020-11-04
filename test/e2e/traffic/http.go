package traffic

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/pkg/errors"

	"github.com/sirupsen/logrus"

	"github.com/travelping/upg-vpp/test/e2e/network"
)

const (
	READ_CHUNK_SIZE = 1000000
	READ_TIMEOUT    = 5 * time.Second
)

type HTTPConfig struct {
	ServerIP        net.IP
	ServerPort      int
	ClientPort      int
	ChunkSize       int
	ChunkCount      int
	ChunkDelay      time.Duration
	Retry           bool
	NoLinger        bool
	UseFakeHostname bool
}

var _ TrafficConfig = &HTTPConfig{}

func (cfg *HTTPConfig) SetServerIP(ip net.IP)     { cfg.ServerIP = ip }
func (cfg *HTTPConfig) SetNoLinger(noLinger bool) { cfg.NoLinger = noLinger }

func (cfg *HTTPConfig) SetDefaults() {
	if cfg.ClientPort == 0 {
		cfg.ClientPort = 80
	}
	if cfg.ServerPort == 0 {
		cfg.ServerPort = cfg.ClientPort
	}
	if cfg.ChunkSize == 0 {
		cfg.ChunkSize = 1000000
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
	if hs.cfg.ServerIP.To4() == nil {
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

func (hc *HTTPClient) downloadURL() string {
	portSuffix := ""
	if hc.cfg.ClientPort != 80 {
		portSuffix = fmt.Sprintf(":%d", hc.cfg.ClientPort)
	}
	var hostname string
	switch {
	case hc.cfg.UseFakeHostname:
		hostname = ipToFakeHostname(hc.cfg.ServerIP)
	case hc.cfg.ServerIP.To4() == nil:
		hostname = fmt.Sprintf("[%s]", hc.cfg.ServerIP)
	default:
		hostname = hc.cfg.ServerIP.String()
	}
	return fmt.Sprintf("http://%s%s/dummy", hostname, portSuffix)
}

func (hc *HTTPClient) Run(ctx context.Context, ns *network.NetNS) error {
	url := hc.downloadURL()
	log := hc.log.WithField("url", url)
	log.Info("downloading")
	c := httpClient(ns, hc.cfg.NoLinger)

	var ts time.Time
	var total int
	chunk := make([]byte, READ_CHUNK_SIZE)
	retry := false
	retrySucceeded := false
OUTER:
	for i := 0; i < 10 && !retrySucceeded; i++ {
		ctx, cancel := context.WithCancel(ctx)
		timer := time.AfterFunc(READ_TIMEOUT, func() { cancel() })
		defer timer.Stop()
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		resp, err := c.Do(req)
		if err != nil {
			if hc.cfg.Retry && ctx.Err() == nil {
				log.WithError(err).Error("HTTP GET failed")
				retry = true
				break
			}
			return errors.Wrap(err, "HTTP GET")
		}
		defer func() {
			resp.Body.Close()
			c.CloseIdleConnections()
		}()

		ts = time.Now()
		total = 0
		for {
			timer.Reset(READ_TIMEOUT)
			n, err := resp.Body.Read(chunk)
			total += n
			if retry && n > 0 {
				retrySucceeded = true
			}
			hc.rec.RecordStats(TrafficStats{ClientReceived: n})
			if err == io.EOF {
				break OUTER
			}
			if err != nil {
				if hc.cfg.Retry && ctx.Err() == nil {
					log.WithError(err).Warn("HTTP GET failed")
					retry = true
					break
				}
				return errors.Wrap(err, "error reading HTTP response")
			}
		}
	}

	elapsed := time.Since(ts)
	log.WithFields(logrus.Fields{
		"total":   total,
		"elapsed": elapsed,
		"Mbps":    float64(total) * 8.0 * float64(time.Second) / (1000000. * float64(elapsed)),
	}).Info("download finished")

	// the point is that if the connection fails, it must be possible to retry afterwards
	if retry && !retrySucceeded {
		return errors.New("retries were attempted, but none succeeded")
	}

	return nil
}
