//go:build linux

package usb

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	maximumSysfsEntries = 4096
	maximumSysfsValue   = 4096
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

type SysfsSource struct {
	USBDevicesRoot string
	DevicesRoot    string
	BlockClassRoot string
	DevRoot        string
	MountInfoPath  string
	Guard          USBGuardLookup
}

func DefaultSysfsSource(guard USBGuardLookup) SysfsSource {
	return SysfsSource{
		USBDevicesRoot: "/sys/bus/usb/devices",
		DevicesRoot:    "/sys/devices",
		BlockClassRoot: "/sys/class/block",
		DevRoot:        "/dev",
		MountInfoPath:  "/proc/self/mountinfo",
		Guard:          guard,
	}
}

func (s SysfsSource) Snapshot(ctx context.Context) ([]Device, error) {
	if s.Guard == nil {
		return nil, errors.New("USBGuard identity lookup is required")
	}
	mounts, err := readMountInfo(s.MountInfoPath)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.USBDevicesRoot)
	if err != nil {
		return nil, err
	}
	if len(entries) > maximumSysfsEntries {
		return nil, errors.New("USB sysfs entry limit exceeded")
	}
	devices := make([]Device, 0)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := entry.Name()
		if strings.Contains(name, ":") || !portPattern.MatchString(name) {
			continue
		}
		linkPath := filepath.Join(s.USBDevicesRoot, name)
		resolved, err := filepath.EvalSymlinks(linkPath)
		if err != nil {
			continue
		}
		if !pathWithin(s.DevicesRoot, resolved) {
			return nil, errors.New("USB sysfs target escaped the devices root")
		}
		vendorID, err := readSmallValue(filepath.Join(resolved, "idVendor"))
		if err != nil {
			continue
		}
		productID, err := readSmallValue(filepath.Join(resolved, "idProduct"))
		if err != nil {
			continue
		}
		bus, err := readUint8(filepath.Join(resolved, "busnum"))
		if err != nil {
			return nil, err
		}
		address, err := readUint8(filepath.Join(resolved, "devnum"))
		if err != nil {
			return nil, err
		}
		serial, _ := readOptionalSmallValue(filepath.Join(resolved, "serial"))
		model, _ := readOptionalSmallValue(filepath.Join(resolved, "product"))
		interfaces, err := s.readInterfaces(name)
		if err != nil || len(interfaces) == 0 {
			continue
		}
		blocks, err := findBlockNames(resolved)
		if err != nil {
			return nil, err
		}
		if len(blocks) != 1 {
			// Multi-LUN and otherwise ambiguous devices are not accepted in v1.
			continue
		}
		identity := Identity{
			VendorID: vendorID, ProductID: productID, Serial: serial,
			Interfaces: interfaces, PortPath: name, Model: model,
		}
		hash, err := s.Guard.Hash(ctx, GuardProbe{
			VendorID: vendorID, ProductID: productID, Serial: serial,
			PortPath: name, Interfaces: append([]string(nil), interfaces...),
		})
		if err != nil {
			return nil, errors.New("USBGuard identity lookup failed")
		}
		identity.USBGuardHash = hash
		blockName := blocks[0]
		blockPath := filepath.Join(s.DevRoot, blockName)
		sectors, err := readUint64(filepath.Join(s.BlockClassRoot, blockName, "size"))
		if err != nil || sectors == 0 || sectors > ^uint64(0)/512 {
			return nil, errors.New("USB block capacity is invalid")
		}
		identity.Capacity = sectors * 512
		readOnly, err := readUint64(filepath.Join(s.BlockClassRoot, blockName, "ro"))
		if err != nil || readOnly > 1 {
			return nil, errors.New("USB read-only evidence is invalid")
		}
		deviceNumbers, err := blockDeviceNumbers(s.BlockClassRoot, blockName)
		if err != nil {
			return nil, err
		}
		mounted, hostFilesystem := classifyMounts(deviceNumbers, mounts)
		device := Device{
			Identity: identity, SysfsPath: resolved, BlockPath: blockPath,
			Bus: bus, Address: address, Mounted: mounted,
			ReadOnly: readOnly == 1, HostFilesystem: hostFilesystem,
		}
		device.DeviceID = snapshotDeviceID(identity, bus, address, blockPath)
		devices = append(devices, device)
	}
	return devices, nil
}

func (s SysfsSource) readInterfaces(deviceName string) ([]string, error) {
	entries, err := os.ReadDir(s.USBDevicesRoot)
	if err != nil {
		return nil, err
	}
	interfaces := make([]string, 0, 1)
	prefix := deviceName + ":"
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		path, err := filepath.EvalSymlinks(filepath.Join(s.USBDevicesRoot, entry.Name()))
		if err != nil || !pathWithin(s.DevicesRoot, path) {
			return nil, errors.New("USB interface sysfs target is invalid")
		}
		class, err := readSmallValue(filepath.Join(path, "bInterfaceClass"))
		if err != nil {
			return nil, err
		}
		subclass, err := readSmallValue(filepath.Join(path, "bInterfaceSubClass"))
		if err != nil {
			return nil, err
		}
		protocol, err := readSmallValue(filepath.Join(path, "bInterfaceProtocol"))
		if err != nil {
			return nil, err
		}
		interfaces = append(interfaces, strings.ToLower(class+":"+subclass+":"+protocol))
	}
	return interfaces, nil
}

func findBlockNames(root string) ([]string, error) {
	seen := make(map[string]struct{})
	count := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		count++
		if count > maximumSysfsEntries {
			return errors.New("USB sysfs traversal limit exceeded")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if !entry.IsDir() || filepath.Base(filepath.Dir(path)) != "block" {
			return nil
		}
		seen[entry.Name()] = struct{}{}
		return filepath.SkipDir
	})
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	return result, nil
}

type mountEvidence struct {
	device     string
	mountPoint string
}

func readMountInfo(path string) ([]mountEvidence, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	result := make([]mountEvidence, 0)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			return nil, errors.New("mountinfo record is malformed")
		}
		result = append(result, mountEvidence{device: fields[2], mountPoint: unescapeMountInfo(fields[4])})
		if len(result) > maximumSysfsEntries {
			return nil, errors.New("mountinfo record limit exceeded")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func blockDeviceNumbers(root, blockName string) (map[string]struct{}, error) {
	result := make(map[string]struct{})
	rootPath := filepath.Join(root, blockName)
	value, err := readSmallValue(filepath.Join(rootPath, "dev"))
	if err != nil {
		return nil, err
	}
	result[value] = struct{}{}
	entries, err := os.ReadDir(rootPath)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), blockName) {
			continue
		}
		value, err := readSmallValue(filepath.Join(rootPath, entry.Name(), "dev"))
		if err == nil {
			result[value] = struct{}{}
		}
	}
	return result, nil
}

func classifyMounts(deviceNumbers map[string]struct{}, mounts []mountEvidence) (bool, bool) {
	mounted := false
	host := false
	for _, mount := range mounts {
		if _, exists := deviceNumbers[mount.device]; !exists {
			continue
		}
		mounted = true
		switch mount.mountPoint {
		case "/", "/boot", "/boot/efi", "/efi":
			host = true
		}
	}
	return mounted, host
}

func readSmallValue(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(data) == 0 || len(data) > maximumSysfsValue || strings.IndexByte(string(data), 0) >= 0 {
		return "", errors.New("sysfs value is invalid")
	}
	value := strings.TrimSpace(string(data))
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return "", errors.New("sysfs value is invalid")
	}
	return value, nil
}

func readOptionalSmallValue(path string) (string, error) {
	value, err := readSmallValue(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	return value, err
}

func readUint8(path string) (uint8, error) {
	value, err := readUint64(path)
	if err != nil || value == 0 || value > 255 {
		return 0, errors.New("USB bus/address value is invalid")
	}
	return uint8(value), nil
}

func readUint64(path string) (uint64, error) {
	value, err := readSmallValue(path)
	if err != nil {
		return 0, err
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("numeric sysfs value is invalid")
	}
	return parsed, nil
}

func pathWithin(root, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func unescapeMountInfo(value string) string {
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return replacer.Replace(value)
}
