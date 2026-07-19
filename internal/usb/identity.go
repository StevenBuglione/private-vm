package usb

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

const MassStorageClass = "08"

var (
	hexIDPattern        = regexp.MustCompile(`^[0-9a-f]{4}$`)
	interfacePattern    = regexp.MustCompile(`^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$`)
	portPattern         = regexp.MustCompile(`^[0-9]+(?:-[0-9]+(?:\.[0-9]+)*)$`)
	usbGuardHashPattern = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{16,256}$`)
)

// Identity is the persistent, content-free identity of an enrolled USB
// device. Kernel paths, bus numbers and addresses are deliberately excluded:
// they are volatile observations and can never authorize a later claim.
type Identity struct {
	VendorID     string   `json:"vendor_id"`
	ProductID    string   `json:"product_id"`
	Serial       string   `json:"serial,omitempty"`
	USBGuardHash string   `json:"usbguard_hash"`
	Interfaces   []string `json:"interfaces"`
	Capacity     uint64   `json:"capacity_bytes"`
	PortPath     string   `json:"port_path"`
	PortBound    bool     `json:"port_bound"`
	Model        string   `json:"model,omitempty"`
}

func (i Identity) normalized() Identity {
	i.VendorID = strings.ToLower(strings.TrimSpace(i.VendorID))
	i.ProductID = strings.ToLower(strings.TrimSpace(i.ProductID))
	i.Serial = strings.TrimSpace(i.Serial)
	i.USBGuardHash = strings.TrimSpace(i.USBGuardHash)
	i.PortPath = strings.TrimSpace(i.PortPath)
	i.Model = strings.TrimSpace(i.Model)
	for index := range i.Interfaces {
		i.Interfaces[index] = strings.ToLower(strings.TrimSpace(i.Interfaces[index]))
	}
	sort.Strings(i.Interfaces)
	return i
}

func (i Identity) ValidateForEnrollment() error {
	i = i.normalized()
	if !hexIDPattern.MatchString(i.VendorID) || !hexIDPattern.MatchString(i.ProductID) {
		return errors.New("USB vendor and product IDs must each be four hexadecimal digits")
	}
	if !portPattern.MatchString(i.PortPath) {
		return errors.New("a bounded physical USB port path is required")
	}
	if i.Serial == "" && !i.PortBound {
		return errors.New("a device without a serial requires explicit physical-port binding")
	}
	if len(i.Serial) > 256 || strings.ContainsAny(i.Serial, "\x00\r\n") {
		return errors.New("USB serial is invalid")
	}
	if !usbGuardHashPattern.MatchString(i.USBGuardHash) {
		return errors.New("a valid USBGuard identity hash is required")
	}
	if i.Capacity == 0 {
		return errors.New("capacity must be nonzero")
	}
	if len(i.Interfaces) == 0 || len(i.Interfaces) > 32 {
		return errors.New("a bounded USB interface list is required")
	}
	for index, iface := range i.Interfaces {
		if !interfacePattern.MatchString(iface) {
			return errors.New("USB interface descriptor is invalid")
		}
		if !strings.HasPrefix(iface, MassStorageClass+":") {
			return fmt.Errorf("non-storage USB interface %q is forbidden", iface)
		}
		if index > 0 && iface == i.Interfaces[index-1] {
			return errors.New("duplicate USB interface descriptor is forbidden")
		}
	}
	if len(i.Model) > 256 || strings.ContainsAny(i.Model, "\x00\r\n") {
		return errors.New("USB model is invalid")
	}
	return nil
}

// Matches compares every enrolled identity field. A serial-bearing enrollment
// still pins its observed port so a device move is visible rather than silently
// weakening an existing enrollment.
func (i Identity) Matches(current Identity) bool {
	i = i.normalized()
	current = current.normalized()
	return i.VendorID == current.VendorID &&
		i.ProductID == current.ProductID &&
		i.Serial == current.Serial &&
		i.USBGuardHash == current.USBGuardHash &&
		i.PortPath == current.PortPath &&
		i.PortBound == current.PortBound &&
		i.Capacity == current.Capacity &&
		i.Model == current.Model &&
		slices.Equal(i.Interfaces, current.Interfaces)
}

func (i Identity) fingerprint() ([32]byte, error) {
	i = i.normalized()
	if err := i.ValidateForEnrollment(); err != nil {
		return [32]byte{}, err
	}
	canonical := strings.Join([]string{
		i.VendorID,
		i.ProductID,
		i.Serial,
		i.USBGuardHash,
		i.PortPath,
		fmt.Sprintf("%t", i.PortBound),
		fmt.Sprintf("%d", i.Capacity),
		i.Model,
		strings.Join(i.Interfaces, ","),
	}, "\x00")
	return sha256.Sum256([]byte(canonical)), nil
}

func (i Identity) Fingerprint() (string, error) {
	sum, err := i.fingerprint()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sum[:]), nil
}
