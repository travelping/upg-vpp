// memory_trace.go - 3GPP TS 29.244 GTP-U UP plug-in
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

package vpp

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

type MemoryTraceEntry struct {
	Bytes    uint64
	Count    uint64
	Sample   uint64
	Location string
}

type MemoryTrace []MemoryTraceEntry

func (mt MemoryTrace) FindSuspectedLeak(locationSubsring string, minCount uint64) bool {
	for _, entry := range mt {
		if !strings.Contains(entry.Location, locationSubsring) {
			continue
		}
		if entry.Count >= minCount {
			return true
		}
	}

	return false
}

var titleRx = regexp.MustCompile(`^Bytes\s+Count\s+Sample\s+Traceback$`)
var entryRx = regexp.MustCompile(`^\s*(\d+)\s+(\d+)\s+0x([0-9A-Fa-f]+)\s+(.*)`)
var totalRx = regexp.MustCompile(`^\s*\d+\s+total traced objects`)

func ParseMemoryTrace(src string) (MemoryTrace, error) {
	var r MemoryTrace
	lines := strings.Split(src, "\n")
	gotTitle := false
	var topItemEntry *MemoryTraceEntry
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if titleRx.MatchString(l) {
			gotTitle = true
			continue
		}
		if !gotTitle {
			continue
		}
		if totalRx.MatchString(l) {
			gotTitle = false
			continue
		}

		m := entryRx.FindStringSubmatch(l)
		if m == nil {
			if topItemEntry == nil {
				return nil, errors.Errorf("can't parse the trace line: %s", l)
			}
			newEntry := *topItemEntry
			newEntry.Location = l
			r = append(r, newEntry)
			continue
		}

		bytes, err := strconv.ParseUint(m[1], 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "can't parse N of bytes: %s", l)
		}
		count, err := strconv.ParseUint(m[2], 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "can't parse count: %s", l)
		}
		sample, err := strconv.ParseUint(m[3], 16, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "can't parse sample field: %s", l)
		}
		topItemEntry = &MemoryTraceEntry{
			Bytes:    bytes,
			Count:    count,
			Sample:   sample,
			Location: m[4],
		}
		r = append(r, *topItemEntry)
	}
	return r, nil
}
