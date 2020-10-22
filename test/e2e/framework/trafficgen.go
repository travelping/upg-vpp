package framework

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
)

type TrafficType int

const (
	READ_CHUNK_SIZE             = 1000000
	READ_TIMEOUT                = 15 * time.Second
	MAX_ERRORS                  = 16
	TrafficTypeTCP  TrafficType = 0
	TrafficTypeUDP  TrafficType = 1
)

type TrafficGenConfig struct {
	ClientNS            *NetNS
	ServerNS            *NetNS
	ServerIP            net.IP
	WebServerPort       int
	WebServerListenPort int
	UDPServerPort       int
	UDPTimeout          time.Duration
	ChunkSize           int
	ChunkCount          int
	ChunkDelay          time.Duration
	FinalDelay          time.Duration // used to avoid late TCP packets for traffic counting
	Context             context.Context
	Type                TrafficType
	VerifyStats         bool
	// Set to true to avoid late TCP packets after the end of a connection
	NoLinger bool
}

func (cfg *TrafficGenConfig) setDefaults() {
	if cfg.WebServerPort == 0 {
		cfg.WebServerPort = 80
	}
	if cfg.WebServerListenPort == 0 {
		cfg.WebServerListenPort = cfg.WebServerPort
	}
	if cfg.UDPServerPort == 0 {
		cfg.UDPServerPort = 12345
	}
	if cfg.UDPTimeout == 0 {
		cfg.UDPTimeout = 100 * time.Millisecond
	}
	if cfg.ChunkSize == 0 {
		cfg.ChunkSize = 1000000
	}
	if cfg.ChunkCount == 0 {
		cfg.ChunkCount = 400
	}
	if cfg.Context == nil {
		cfg.Context = context.Background()
	}
}

type TrafficGenStats struct {
	ClientSent     int
	ClientReceived int
	ServerSent     int
	ServerReceived int
}

type TrafficGen struct {
	sync.Mutex
	cfg    TrafficGenConfig
	s      *http.Server
	uc     *net.UDPConn
	errors []string
	stats  TrafficGenStats
}

func NewTrafficGen(cfg TrafficGenConfig) *TrafficGen {
	cfg.setDefaults()
	return &TrafficGen{
		cfg: cfg,
	}
}

func (tg *TrafficGen) recordErrorUnlocked(format string, args ...interface{}) {
	if len(tg.errors) < MAX_ERRORS {
		tg.errors = append(tg.errors, fmt.Sprintf(format, args...))
	}
}

func (tg *TrafficGen) recordError(format string, args ...interface{}) {
	tg.Lock()
	defer tg.Unlock()
	tg.recordErrorUnlocked(format, args...)
}

func (tg *TrafficGen) recordStats(clientSent, clientReceived, serverSent, serverReceived int) {
	tg.Lock()
	defer tg.Unlock()
	tg.stats.ClientSent += clientSent
	tg.stats.ClientReceived += clientReceived
	tg.stats.ServerSent += serverSent
	tg.stats.ServerReceived += serverReceived
}

func (tg *TrafficGen) Verify() error {
	tg.Lock()
	defer tg.Unlock()
	if tg.cfg.VerifyStats {
		if tg.stats.ClientSent != tg.stats.ServerReceived {
			tg.recordErrorUnlocked("the client sent %d bytes, but the server received %d",
				tg.stats.ClientSent, tg.stats.ServerReceived)
		}
		if tg.stats.ServerSent != tg.stats.ClientReceived {
			tg.recordErrorUnlocked("the server sent %d bytes, but the client received %d",
				tg.stats.ServerSent, tg.stats.ClientReceived)
		}
	}
	if len(tg.errors) == 0 {
		return nil
	}
	return errors.Errorf("errors detected:\n%s\n", strings.Join(tg.errors, "\n"))
}

func (tg *TrafficGen) Stats() TrafficGenStats {
	tg.Lock()
	defer tg.Unlock()
	return tg.stats
}

func (tg *TrafficGen) stopWebserver() {
	if tg.s != nil {
		tg.s.Close()
		tg.s = nil
	}
}

func (tg *TrafficGen) stopUDPServer() {
	if tg.uc != nil {
		tg.uc.Close()
		tg.uc = nil
	}
}

func (tg *TrafficGen) startUDPServer() error {
	if tg.cfg.ChunkSize == 0 {
		panic("zero chunk size")
	}

	uc, err := tg.cfg.ServerNS.ListenUDP(&net.UDPAddr{
		IP:   net.IPv4zero,
		Port: tg.cfg.UDPServerPort,
	})
	if err != nil {
		return errors.Wrap(err, "ListenTCP")
	}
	tg.uc = uc
	tg.cfg.ServerNS.addCleanup(tg.stopUDPServer)

	buf := make([]byte, READ_CHUNK_SIZE)
	go func() {
		for {
			n, addr, err := uc.ReadFromUDP(buf)
			if err != nil {
				// TODO: do errors.Is(err, net.ErrClosed) check to see if
				// we have a error here after switching
				// to newer Go version that has net.ErrClosed
				return
			}
			tg.recordStats(0, 0, 0, n)

			if n != tg.cfg.ChunkSize {
				tg.recordError("bad udp packet size: %d instead of %d", n, tg.cfg.ChunkSize)
			} else {
				buf[0] = '<'
			}

			if _, err := uc.WriteTo(buf[0:n], addr); err != nil {
				tg.recordError("udp send: %v", err)
			} else {
				tg.recordStats(0, 0, n, 0)
			}
		}
	}()
	return nil
}

func (tg *TrafficGen) startWebserver() error {
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
				tg.recordStats(0, 0, len(chunk), 0)
				if tg.cfg.ChunkDelay > 0 {
					<-time.After(tg.cfg.ChunkDelay)
				}
			}
		}),
	}

	l, err := tg.cfg.ServerNS.ListenTCP(fmt.Sprintf("0.0.0.0:%d", tg.cfg.WebServerListenPort))
	if err != nil {
		return errors.Wrap(err, "ListenTCP")
	}

	tg.cfg.ServerNS.addCleanup(tg.stopWebserver)
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

func (tg *TrafficGen) simulateDownload() error {
	portSuffix := ""
	if tg.cfg.WebServerPort != 80 {
		portSuffix = fmt.Sprintf(":%d", tg.cfg.WebServerPort)
	}
	url := fmt.Sprintf("http://%s%s/dummy", tg.cfg.ServerIP, portSuffix)
	fmt.Printf("*** downloading from %s\n", url)

	dialContext := tg.cfg.ClientNS.DialContext
	if tg.cfg.NoLinger {
		dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := tg.cfg.ClientNS.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetLinger(0)
			}
			return conn, nil
		}
	}

	c := http.Client{
		// Timeout: READ_TIMEOUT,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	ctx, cancel := context.WithCancel(tg.cfg.Context)
	timer := time.AfterFunc(READ_TIMEOUT, func() { cancel() })
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := c.Do(req)
	if err != nil {
		return errors.Wrap(err, "HTTP GET")
	}
	defer resp.Body.Close()

	ts := time.Now()
	total := 0
	chunk := make([]byte, READ_CHUNK_SIZE)
	for {
		timer.Reset(READ_TIMEOUT)
		n, err := resp.Body.Read(chunk)
		total += n
		tg.recordStats(0, n, 0, 0)
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "error reading HTTP response")
		}
	}

	elapsed := time.Since(ts)
	fmt.Printf("*** downloaded %d bytes in %s (~%g Mbps)\n",
		total, elapsed,
		float64(total)*8.0*float64(time.Second)/(1000000.*float64(elapsed)))

	return nil
}

func (tg *TrafficGen) genUDPPacket(n int, buf []byte) {
	buf[0] = '>'
	if len(buf) > 1 {
		s := strconv.Itoa(n)
		j := len(s) - 1
		for i := len(buf) - 1; i > 0; i-- {
			if j >= 0 {
				buf[i] = s[j]
				j--
			} else {
				buf[i] = '0'
			}
		}
	}
}

func (tg *TrafficGen) udpPing() error {
	if tg.cfg.ChunkSize == 0 {
		return errors.New("zero chunk size")
	}

	c, err := tg.cfg.ClientNS.DialUDP(
		&net.UDPAddr{
			IP: tg.cfg.ClientNS.IPNet.IP,
		},
		&net.UDPAddr{
			IP:   tg.cfg.ServerIP,
			Port: tg.cfg.UDPServerPort,
		})
	if err != nil {
		return errors.Wrap(err, "DialUDP")
	}

	sendBuf := make([]byte, tg.cfg.ChunkSize)
	recvBuf := make([]byte, tg.cfg.ChunkSize)
	for i := 0; i < tg.cfg.ChunkCount; i++ {
		tg.genUDPPacket(i, sendBuf)
		if _, err := c.Write(sendBuf); err != nil {
			return errors.Wrap(err, "udp send")
		}
		tg.recordStats(len(sendBuf), 0, 0, 0)
		c.SetReadDeadline(time.Now().Add(tg.cfg.UDPTimeout))
		n, _, err := c.ReadFromUDP(recvBuf)
		if err != nil {
			return errors.Wrap(err, "udp receive")
		}
		tg.recordStats(0, n, 0, 0)
		if n != len(sendBuf) {
			tg.recordError("recv length mismatch: %d instead of %d bytes: %q", n, len(sendBuf), string(recvBuf[:n]))
			continue
		}
		if recvBuf[0] != '<' || string(recvBuf[1:]) != string(sendBuf[1:]) {
			tg.recordError("recv mismatch: response %q for request %q", string(recvBuf), string(sendBuf))
		}
		if tg.cfg.ChunkDelay > 0 {
			<-time.After(tg.cfg.ChunkDelay)
		}
	}

	return nil
}

func (tg *TrafficGen) Run() error {
	var err error
	switch tg.cfg.Type {
	case TrafficTypeTCP:
		if err := tg.startWebserver(); err != nil {
			tg.recordError("starting webserver: %v", err)
		} else if err = tg.simulateDownload(); err != nil {
			tg.recordError("download error: %v", err)
		}
	case TrafficTypeUDP:
		if err := tg.startUDPServer(); err != nil {
			tg.recordError("starting udp server: %v", err)
		} else if err = tg.udpPing(); err != nil {
			tg.recordError("udp ping error: %v", err)
		}
	default:
		panic("bad traffic type")
	}
	if err == nil && tg.cfg.FinalDelay != 0 {
		// no immediate failure
		<-time.After(tg.cfg.FinalDelay)
	}

	stats := tg.Stats()
	fmt.Printf("* Stats (bytes): client sent: %d, client received: %d, server sent: %d, server received %d\n",
		stats.ClientSent,
		stats.ClientReceived,
		stats.ServerSent,
		stats.ServerReceived)

	return tg.Verify()
}

func (tg *TrafficGen) Start() chan error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- tg.Run()
	}()
	return errCh
}
