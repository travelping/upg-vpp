package framework

import (
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/pkg/errors"
)

type TrafficGenConfig struct {
	ClientNS         *NetNS
	ServerNS         *NetNS
	ServerIP         net.IP
	ServerPort       int
	ServerListenPort int
	ChunkSize        int
	ChunkCount       int
	ChunkDelay       time.Duration
}

func (cfg *TrafficGenConfig) setDefaults() {
	if cfg.ServerPort == 0 {
		cfg.ServerPort = 80
	}
	if cfg.ServerListenPort == 0 {
		cfg.ServerListenPort = cfg.ServerPort
	}
	if cfg.ChunkSize == 0 {
		cfg.ChunkSize = 1000000
	}
	if cfg.ChunkCount == 0 {
		cfg.ChunkCount = 400
	}
}

type TrafficGen struct {
	cfg TrafficGenConfig
	s   *http.Server
}

func NewTrafficGen(cfg TrafficGenConfig) *TrafficGen {
	cfg.setDefaults()
	return &TrafficGen{
		cfg: cfg,
	}
}

func (tg *TrafficGen) StopWebserver() {
	if tg.s != nil {
		tg.s.Close()
		tg.s = nil
	}
}

func (tg *TrafficGen) StartWebserver() error {
	if tg.s != nil {
		return nil
	}

	chunk := make([]byte, tg.cfg.ChunkSize)
	if _, err := rand.Read(chunk); err != nil {
		return errors.Wrap(err, "rand read")
	}

	tg.s = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			fileSize := tg.cfg.ChunkCount * tg.cfg.ChunkSize
			w.Header().Set("Content-Length", strconv.Itoa(fileSize))
			for i := 0; i < tg.cfg.ChunkCount; i++ {
				_, err := w.Write(chunk)
				if err != nil {
					// FIXME
					log.Printf("Error serving the file: %v", err)
					break
				}
				if tg.cfg.ChunkDelay > 0 {
					<-time.After(tg.cfg.ChunkDelay)
				}
			}
		}),
	}

	l, err := tg.cfg.ServerNS.ListenTCP(fmt.Sprintf("0.0.0.0:%d", tg.cfg.ServerListenPort))
	if err != nil {
		return errors.Wrap(err, "ListenTCP")
	}

	tg.cfg.ServerNS.addCleanup(tg.StopWebserver)
	go func() {
		switch err := tg.s.Serve(l); {
		case err == http.ErrServerClosed:
			break
		case err != nil:
			log.Printf("Error serving http: %v", err)
		}
	}()

	return nil
}

func (tg *TrafficGen) SimulateDownload() error {
	portSuffix := ""
	if tg.cfg.ServerPort != 80 {
		portSuffix = fmt.Sprintf(":%d", tg.cfg.ServerPort)
	}
	url := fmt.Sprintf("http://%s%s/dummy", tg.cfg.ServerIP, portSuffix)
	fmt.Printf("*** downloading from %s\n", url)

	c := http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           tg.cfg.ClientNS.DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	resp, err := c.Get(url)
	if err != nil {
		return errors.Wrap(err, "HTTP GET")
	}
	defer resp.Body.Close()

	ts := time.Now()
	content, err := ioutil.ReadAll(resp.Body)

	elapsed := time.Since(ts)
	fmt.Printf("*** downloaded %d bytes in %s (~%g Mbps)\n",
		len(content), elapsed,
		float64(len(content))*8.0*float64(time.Second)/(1000000.*float64(elapsed)))

	return nil
}
