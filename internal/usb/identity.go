package usb

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

type Identity struct {
	VendorID   string   `json:"vendorId"`
	ProductID  string   `json:"productId"`
	Serial     string   `json:"serial"`
	Interfaces []string `json:"interfaces"`
	Capacity   uint64   `json:"capacityBytes"`
	PortPath   string   `json:"portPath"`
}

func (i Identity) ValidateForEnrollment() error {
	if i.VendorID == "" || i.ProductID == "" || i.Serial == "" || i.PortPath == "" {
		return errors.New("VID, PID, serial and physical port path are required")
	}
	if i.Capacity == 0 {
		return errors.New("capacity must be nonzero")
	}
	if len(i.Interfaces) == 0 {
		return errors.New("USB interface list required")
	}
	for _, iface := range i.Interfaces {
		normalized := strings.ToLower(iface)
		// USB class 08 is mass storage. Exact subclass/protocol remain recorded.
		if !strings.HasPrefix(normalized, "08:") {
			return fmt.Errorf("non-storage USB interface %q is forbidden", iface)
		}
	}
	return nil
}

func (i Identity) Matches(current Identity) bool {
	if i.VendorID != current.VendorID ||
		i.ProductID != current.ProductID ||
		i.Serial != current.Serial ||
		i.PortPath != current.PortPath ||
		i.Capacity != current.Capacity {
		return false
	}
	a, b := append([]string(nil), i.Interfaces...), append([]string(nil), current.Interfaces...)
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, "\x00") == strings.Join(b, "\x00")
}
