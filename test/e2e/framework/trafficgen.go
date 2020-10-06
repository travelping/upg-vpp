package framework

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/pkg/errors"
)

const (
	VPP_WS_FILE_SIZE  = 60000000
	GO_WS_CHUNK_SIZE  = 1000000
	GO_WS_CHUNK_COUNT = 40
	GO_WS_FILE_SIZE   = GO_WS_CHUNK_COUNT * GO_WS_CHUNK_SIZE
)

type TrafficGenConfig struct {
	ClientNS         *NetNS
	ServerNS         *NetNS
	ServerIP         net.IP
	ServerPort       int
	ServerListenPort int
}

type TrafficGen struct {
	cfg TrafficGenConfig
	s   *http.Server
}

func NewTrafficGen(cfg TrafficGenConfig) *TrafficGen {
	return &TrafficGen{
		cfg: cfg,
	}
}

// TODO: pre-generate random chunk

// func (tg *TrafficGenerator) downloadURL() string {
// 	return fmt.Sprintf("http://%s/dummy", VPP_CLIENT_IP)
// }

func (tg *TrafficGen) TearDown() {
	if tg.s != nil {
		tg.s.Close()
		tg.s = nil
	}
}

func (tg *TrafficGen) StartWebserver() error {
	if tg.s != nil {
		return nil
	}

	chunk := make([]byte, GO_WS_CHUNK_SIZE)
	tg.s = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.Itoa(GO_WS_FILE_SIZE))
			for i := 0; i < GO_WS_CHUNK_COUNT; i++ {
				_, err := w.Write(chunk)
				if err != nil {
					// FIXME
					log.Printf("Error serving the file: %v", err)
					break
				}
			}
		}),
	}

	l, err := tg.cfg.ServerNS.ListenTCP(fmt.Sprintf("0.0.0.0:%d", tg.cfg.ServerListenPort))
	if err != nil {
		return errors.Wrap(err, "ListenTCP")
	}

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

func (tg *TrafficGen) simulateDownload(url string, expectedFileSize int) error {
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

	if len(content) != expectedFileSize {
		return errors.Errorf("bad file size. Expected %d, got %d bytes",
			expectedFileSize, len(content))
	}

	elapsed := time.Since(ts)
	fmt.Printf("*** downloaded %d bytes in %s (~%g Mbps)\n",
		len(content), elapsed,
		float64(len(content))*8.0*float64(time.Second)/(1000000.*float64(elapsed)))

	return nil
}

func (tg *TrafficGen) SimulateDownloadThroughProxy() error {
	if err := tg.StartWebserver(); err != nil {
		return err
	}

	if err := tg.simulateDownload(fmt.Sprintf("http://%s:%d/dummy", tg.cfg.ServerIP, tg.cfg.ServerPort), GO_WS_FILE_SIZE); err != nil {
		return err
	}

	return nil
}

func (tg *TrafficGen) SimulateDownloadFromVPPWebServer() error {
	return tg.simulateDownload(fmt.Sprintf("http://%s/dummy", tg.cfg.ServerIP), VPP_WS_FILE_SIZE)
}
