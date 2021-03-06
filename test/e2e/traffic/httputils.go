// httputils.go - 3GPP TS 29.244 GTP-U UP plug-in
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
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/travelping/upg-vpp/test/e2e/network"
)

const (
	FakeHostnamePrefixV4 = "theserver4-"
	FakeHostnamePrefixV6 = "theserver6-"
)

func fakeHostnameToAddress(s string) string {
	// theserver4-1-2-3-4        -> 1.2.3.4
	// theserver6-2001-db8-12--3 -> 2001:db8:12::3
	// This trick is used to trigger app detection while not using real
	// hostname resolution, while not tweaking net.Http too much
	switch {
	case strings.HasPrefix(s, FakeHostnamePrefixV4):
		return strings.ReplaceAll(s[len(FakeHostnamePrefixV4):], "-", ".")
	case strings.HasPrefix(s, FakeHostnamePrefixV6):
		parts := strings.Split(s, ":")
		if len(parts) != 2 {
			return s
		}
		return net.JoinHostPort(strings.ReplaceAll(parts[0][len(FakeHostnamePrefixV6):], "-", ":"),
			parts[1])
	default:
		return s
	}
}

func ipToFakeHostname(ip net.IP) string {
	if ip.To4() == nil {
		return FakeHostnamePrefixV6 + strings.ReplaceAll(ip.String(), ":", "-")
	}
	return FakeHostnamePrefixV4 + strings.ReplaceAll(ip.String(), ".", "-")
}

func httpClient(ns *network.NetNS, noLinger bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				address = fakeHostnameToAddress(address)
				conn, err := ns.DialContext(ctx, network, address)
				if err != nil {
					return nil, err
				}
				if noLinger {
					if tcpConn, ok := conn.(*net.TCPConn); ok {
						tcpConn.SetLinger(0)
					}
				}
				return conn, nil
			},
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}
