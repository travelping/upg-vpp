package framework

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const (
	CAPTURE_DECODER = "Ethernet"
)

type CaptureConfig struct {
	Iface    string
	PCAPPath string
	Snaplen  int
	TargetNS *NetNS
}

type CaptureStats struct {
	Count      int64
	Bytes      int64
	Start      time.Time
	Errors     int64
	Truncated  int64
	LayerTypes map[gopacket.LayerType]int64
}

type Capture struct {
	sync.Mutex
	cfg           CaptureConfig
	Stats         CaptureStats
	stopCh        chan struct{}
	trafficCounts map[FiveTuple]uint64
}

func NewCapture(cfg CaptureConfig) *Capture {
	return &Capture{
		cfg:           cfg,
		trafficCounts: make(map[FiveTuple]uint64),
	}
}

func (c *Capture) makeHandle() (*pcap.Handle, error) {
	inactive, err := pcap.NewInactiveHandle(c.cfg.Iface)
	if err != nil {
		return nil, errors.Wrap(err, "could not create")
	}
	defer inactive.CleanUp()
	if err = inactive.SetSnapLen(c.cfg.Snaplen); err != nil {
		return nil, errors.Wrap(err, "could not set snap length")
	} else if err = inactive.SetPromisc(true); err != nil {
		return nil, errors.Wrap(err, "could not set promisc mode")
	} else if err = inactive.SetTimeout(time.Second); err != nil {
		return nil, errors.Wrap(err, "could not set timeout")
	}
	if handle, err := inactive.Activate(); err != nil {
		return nil, errors.Wrap(err, "PCAP Activate error")
	} else {
		return handle, nil
	}
}

func (c *Capture) Stop() {
	if c.stopCh != nil {
		close(c.stopCh)
		c.stopCh = nil
	}
}

func (c *Capture) Start() error {
	if c.stopCh != nil {
		return nil
	}

	fmt.Printf("* starting capture for %s to %s\n", c.cfg.Iface, c.cfg.PCAPPath)
	f, err := os.Create(c.cfg.PCAPPath)
	if err != nil {
		return errors.Wrapf(err, "error creating pcap file %q", c.cfg.PCAPPath)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(uint32(c.cfg.Snaplen), layers.LinkTypeEthernet); err != nil {
		f.Close()
		os.Remove(c.cfg.PCAPPath)
		return errors.Wrapf(err, "error writing pcap header")
	}

	var handle *pcap.Handle
	if c.cfg.TargetNS != nil {
		err = c.cfg.TargetNS.Do(func() error {
			handle, err = c.makeHandle()
			return err
		})
	} else {
		handle, err = c.makeHandle()
	}
	if err != nil {
		f.Close()
		os.Remove(c.cfg.PCAPPath)
		return err
	}

	dec, ok := gopacket.DecodersByLayerName[CAPTURE_DECODER]
	if !ok {
		f.Close()
		os.Remove(c.cfg.PCAPPath)
		log.Panicf("No decoder named %s", CAPTURE_DECODER)
	}

	source := gopacket.NewPacketSource(handle, dec)
	source.NoCopy = true
	source.DecodeStreamsAsDatagrams = true

	fmt.Println("* Starting to read packets")
	c.Stats = CaptureStats{
		Start:      time.Now(),
		LayerTypes: make(map[gopacket.LayerType]int64),
	}
	c.stopCh = make(chan struct{})
	stopCh := c.stopCh
	if c.cfg.TargetNS != nil {
		c.cfg.TargetNS.addCleanup(c.Stop)
	}

	go func() {
		defer func() {
			f.Close()
			handle.Close()
		}()

		for {
			select {
			case packet := <-source.Packets():
				fiveTuple, globTuple, plen := packet5TupleAndLength(packet)
				if fiveTuple != "" {
					c.Lock()
					c.trafficCounts[fiveTuple] += uint64(plen)
					c.trafficCounts[globTuple] += uint64(plen)
					c.Unlock()
				}
				if err := w.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
					fmt.Printf("Error writing packet: %s\n", err)
					return
				}
			case <-stopCh:
				return
			}
		}
	}()

	return nil
}

func (c *Capture) GetTrafficCount(ft FiveTuple) uint64 {
	c.Lock()
	defer c.Unlock()
	return c.trafficCounts[ft]
}

type FiveTuple string

func Make5Tuple(srcIP net.IP, srcPort int, dstIP net.IP, dstPort int, proto layers.IPProtocol) FiveTuple {
	srcPortStr := "*"
	if srcPort >= 0 {
		srcPortStr = strconv.Itoa(srcPort)
	}
	dstPortStr := "*"
	if dstPort >= 0 {
		dstPortStr = strconv.Itoa(dstPort)
	}
	return FiveTuple(fmt.Sprintf("%s %s:%s -> %s:%s", proto, srcIP, srcPortStr, dstIP, dstPortStr))
}

func packet5TupleAndLength(p gopacket.Packet) (FiveTuple, FiveTuple, uint16) {
	var plen uint16
	var srcIP, dstIP net.IP
	var srcPort, dstPort uint16
	var proto layers.IPProtocol

	layer := p.Layer(layers.LayerTypeIPv4)
	if layer != nil {
		l := layer.(*layers.IPv4)
		srcIP = l.SrcIP
		dstIP = l.DstIP
		proto = l.Protocol
		plen = l.Length
	} else {
		layer = p.Layer(layers.LayerTypeIPv6)
		if layer != nil {
			l := layer.(*layers.IPv6)
			srcIP = l.SrcIP
			dstIP = l.DstIP
			proto = l.NextHeader
			plen = l.Length + 40
		} else {
			return "", "", 0
		}
	}

	layer = p.Layer(layers.LayerTypeTCP)
	if layer != nil {
		l := layer.(*layers.TCP)
		srcPort = uint16(l.SrcPort)
		dstPort = uint16(l.DstPort)
	} else {
		layer = p.Layer(layers.LayerTypeUDP)
		if layer != nil {
			l := layer.(*layers.UDP)
			srcPort = uint16(l.SrcPort)
			dstPort = uint16(l.DstPort)
		}
	}

	return Make5Tuple(srcIP, int(srcPort), dstIP, int(dstPort), proto),
		Make5Tuple(srcIP, -1, dstIP, -1, proto), plen
}
