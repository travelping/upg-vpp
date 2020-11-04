// +build linux

package network

import (
	"github.com/pkg/errors"

	"github.com/safchain/ethtool"
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
