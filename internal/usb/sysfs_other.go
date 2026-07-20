//go:build !linux

package usb

import (
	"context"
	"errors"
)

type USBGuardLookup interface {
	Hash(context.Context, GuardProbe) (string, error)
}

type GuardProbe struct {
	VendorID   string
	ProductID  string
	Serial     string
	PortPath   string
	Interfaces []string
}

type SysfsSource struct{ Guard USBGuardLookup }

func DefaultSysfsSource(guard USBGuardLookup) SysfsSource { return SysfsSource{Guard: guard} }

func (SysfsSource) Snapshot(context.Context) ([]Device, error) {
	return nil, errors.New("USB sysfs discovery is supported only on Linux")
}
