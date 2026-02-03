// netns_linux.go - 3GPP TS 29.244 GTP-U UP plug-in
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

// +build linux

package network

import (
	"github.com/pkg/errors"

	"github.com/safchain/ethtool"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func (netns *NetNS) disableOffloading(linkName string) error {
	return netns.Do(func() error {
		et, err := ethtool.NewEthtool()
		if err != nil {
			return errors.Wrap(err, "NewEthtool")
		}
		features, err := et.Features(linkName)
		if err != nil {
			return errors.Wrap(err, "Features")
		}
		updateFeatures := make(map[string]bool)
		for name, value := range features {
			if ethFeatureRx.MatchString(name) && value {
				updateFeatures[name] = false
			}
		}
		if len(updateFeatures) > 0 {
			if err := et.Change(linkName, updateFeatures); err != nil {
				return errors.Wrapf(err, "change eth features: %#v", updateFeatures)
			}
		}
		return nil
	})
}

func (netns *NetNS) SetNetem(linkName string, attrs NetemAttrs) error {
	return netns.Do(func() error {
		link, err := netlink.LinkByName(linkName)
		if err != nil {
			return errors.Wrap(err, "locating client link in the client netns")
		}
		if err := netlink.QdiscAdd(netlink.NewNetem(
			netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_ROOT,
			},
			netlink.NetemQdiscAttrs(attrs))); err != nil {
			return errors.Wrap(err, "netem failed")
		}
		logrus.WithFields(logrus.Fields{
			"ns":   netns.Name,
			"link": linkName,
		}).Debug("netem qdisc added")
		return nil
	})
}

func (netns *NetNS) DelNetem(linkName string) (bool, error) {
	found := false
	err := netns.Do(func() error {
		link, err := netlink.LinkByName(linkName)
		if err != nil {
			return errors.Wrap(err, "locating client link in the client netns")
		}
		qdiscs, err := netlink.QdiscList(link)
		if err != nil {
			return errors.Wrap(err, "listing qdiscs failed")
		}
		if len(qdiscs) > 0 {
			for _, qdisc := range qdiscs {
				if _, ok := qdisc.(*netlink.Netem); !ok {
					continue
				}
				if err := netlink.QdiscDel(qdisc); err != nil {
					return errors.Wrap(err, "clearing netem qdisc failed")
				}
				logrus.WithFields(logrus.Fields{
					"ns":   netns.Name,
					"link": linkName,
				}).Debug("netem qdisc removed")
				found = true
			}
		}
		return nil
	})
	return found, err
}
