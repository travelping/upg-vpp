// capture.go - 3GPP TS 29.244 GTP-U UP plug-in
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

package network

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/tomb.v2"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/sirupsen/logrus"
)

const (
	FinalIdleDuraton = 3 * time.Second
)

type CaptureConfig struct {
	Iface     string
	PCAPPath  string
	Snaplen   int
	TargetNS  *NetNS
	LayerType string
}

func (cfg *CaptureConfig) SetDefaults() {
	if cfg.LayerType == "" {
		cfg.LayerType = "Ethernet"
	}
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
	cfg             CaptureConfig
	Stats           CaptureStats
	trafficCounts   map[FiveTuple]uint64
	l4TrafficCounts map[FiveTuple]uint64
	log             *logrus.Entry
	t               *tomb.Tomb
}

func NewCapture(cfg CaptureConfig) *Capture {
	cfg.SetDefaults()
	return &Capture{
		cfg:             cfg,
		trafficCounts:   make(map[FiveTuple]uint64),
		l4TrafficCounts: make(map[FiveTuple]uint64),
		log: logrus.WithFields(logrus.Fields{
			"ns":    cfg.TargetNS.Name,
			"iface": cfg.Iface,
		}),
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

func (c *Capture) Stop() error {
	if c.t == nil {
		return nil
	}
	c.t.Kill(nil)
	err := c.t.Wait()
	c.t = nil
	return err
}

func (c *Capture) Start() error {
	if c.t != nil {
		return nil
	}

	c.log.WithField("pcapPath", c.cfg.PCAPPath).Info("starting capture")
	f, err := os.Create(c.cfg.PCAPPath)
	if err != nil {
		return errors.Wrapf(err, "error creating pcap file %q", c.cfg.PCAPPath)
	}
	w := pcapgo.NewWriter(f)
	var linkType layers.LinkType
	switch c.cfg.LayerType {
	case "Ethernet":
		linkType = layers.LinkTypeEthernet
	case "IPv4":
		linkType = layers.LinkTypeIPv4
	case "IPv6":
		linkType = layers.LinkTypeIPv6
	default:
		panic("bad layer type: " + c.cfg.LayerType)
	}

	if err := w.WriteFileHeader(uint32(c.cfg.Snaplen), linkType); err != nil {
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

	dec, ok := gopacket.DecodersByLayerName[c.cfg.LayerType]
	if !ok {
		f.Close()
		os.Remove(c.cfg.PCAPPath)
		log.Panicf("No decoder named %s", c.cfg.LayerType)
	}

	source := gopacket.NewPacketSource(handle, dec)
	source.NoCopy = true
	source.DecodeStreamsAsDatagrams = true

	c.Stats = CaptureStats{
		Start:      time.Now(),
		LayerTypes: make(map[gopacket.LayerType]int64),
	}
	c.t = &tomb.Tomb{}
	if c.cfg.TargetNS != nil {
		c.cfg.TargetNS.AddCleanup(func() {
			if err := c.Stop(); err != nil {
				c.log.WithError(err).Error("error capturing packets")
			}
		})
	}

	c.t.Go(func() error {
		defer func() {
			f.Close()
		}()

		var finalIdleTimer *time.Timer
		var finalIdleCh <-chan time.Time
		dying := c.t.Dying()
		for {
			select {
			case packet := <-source.Packets():
				l3, next := decapLayers(packet)
				if l3 != nil {
					fiveTuple, globTuple, plen := packet5TupleAndLength(l3, next)
					c.Lock()
					c.trafficCounts[fiveTuple] += uint64(plen)
					c.trafficCounts[globTuple] += uint64(plen)
					if next != nil {
						l4Len := uint64(len(next.LayerPayload()))
						c.l4TrafficCounts[fiveTuple] += l4Len
						c.l4TrafficCounts[globTuple] += l4Len
					}
					c.Unlock()
				}
				if err := w.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
					return errors.Wrap(err, "error writing captured packet")
				}
				if finalIdleTimer != nil {
					finalIdleTimer.Stop()
					finalIdleTimer = time.NewTimer(FinalIdleDuraton)
					finalIdleCh = finalIdleTimer.C
				}
			case <-dying:
				dying = nil
				if finalIdleTimer == nil {
					finalIdleTimer = time.NewTimer(FinalIdleDuraton)
					finalIdleCh = finalIdleTimer.C
				}
			case <-finalIdleCh:
				return nil
			}
		}
	})

	return nil
}

func (c *Capture) GetTrafficCount(ft FiveTuple) uint64 {
	c.Lock()
	defer c.Unlock()
	return c.trafficCounts[ft]
}

func (c *Capture) GetL4TrafficCount(ft FiveTuple) uint64 {
	c.Lock()
	defer c.Unlock()
	return c.l4TrafficCounts[ft]
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

// decapLayers returns an IPv4 or IPv6 layer from the packet,
// along with a following TCP/UDP/ICMPv4/ICMPv6 layer.
// If there's GTP-U encapsulation, the layers after the
// GTPU one are used
func decapLayers(p gopacket.Packet) (gopacket.Layer, gopacket.Layer) {
	var l3, next gopacket.Layer // ICMP is not really "l4"
	gotGTPU := false
	for _, l := range p.Layers() {
		switch l.LayerType() {
		case layers.LayerTypeGTPv1U:
			gotGTPU = true
		case layers.LayerTypeIPv4, layers.LayerTypeIPv6:
			if l3 != nil && !gotGTPU {
				// some unknown kind of encapsulation
				continue
			}
			l3 = l
			next = nil
		case layers.LayerTypeICMPv4, layers.LayerTypeICMPv6,
			layers.LayerTypeTCP, layers.LayerTypeUDP:
			if l3 != nil {
				next = l
			}
		}
	}
	return l3, next
}

func packet5TupleAndLength(l3, next gopacket.Layer) (FiveTuple, FiveTuple, uint16) {
	var plen uint16
	var srcIP, dstIP net.IP
	var srcPort, dstPort uint16
	var proto layers.IPProtocol

	switch l3.LayerType() {
	case layers.LayerTypeIPv4:
		l := l3.(*layers.IPv4)
		srcIP = l.SrcIP
		dstIP = l.DstIP
		proto = l.Protocol
		plen = l.Length
	case layers.LayerTypeIPv6:
		l := l3.(*layers.IPv6)
		srcIP = l.SrcIP
		dstIP = l.DstIP
		proto = l.NextHeader
		plen = l.Length + 40
	default:
		// shouldn't be here
		panic("BUG: bad layer type")
	}

	if next != nil {
		switch next.LayerType() {
		case layers.LayerTypeTCP:
			l := next.(*layers.TCP)
			srcPort = uint16(l.SrcPort)
			dstPort = uint16(l.DstPort)
		case layers.LayerTypeUDP:
			l := next.(*layers.UDP)
			srcPort = uint16(l.SrcPort)
			dstPort = uint16(l.DstPort)
		}
	}

	return Make5Tuple(srcIP, int(srcPort), dstIP, int(dstPort), proto),
		Make5Tuple(srcIP, -1, dstIP, -1, proto), plen
}
