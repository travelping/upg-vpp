package framework

import (
	"fmt"
	"log"
	"os"
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
	cfg    CaptureConfig
	Stats  CaptureStats
	stopCh chan struct{}
}

func NewCapture(cfg CaptureConfig) *Capture {
	return &Capture{
		cfg: cfg,
	}
}

func (c *Capture) makeSource() (*pcap.Handle, error) {
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
	// if *tstype != "" {
	// 	if t, err := pcap.TimestampSourceFromString(*tstype); err != nil {
	// 		log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
	// 	} else if err := inactive.SetTimestampSource(t); err != nil {
	// 		log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
	// 	}
	// }
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
			handle, err = c.makeSource()
			return err
		})
	} else {
		handle, err = c.makeSource()
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
