package usb

import (
	"bufio"
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/StevenBuglione/private-vm/internal/commandexec"
)

const maximumUSBGuardRecords = 256

var (
	guardIDPattern        = regexp.MustCompile(`\bid ([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4})(?:\s|$)`)
	guardSerialPattern    = regexp.MustCompile(`\bserial "([^"]*)"`)
	guardHashFieldPattern = regexp.MustCompile(`\bhash "([A-Za-z0-9+/=_-]{16,256})"`)
	guardPortFieldPattern = regexp.MustCompile(`\bvia-port "([0-9]+(?:-[0-9]+(?:\.[0-9]+)*)?)"`)
	guardInterfacePattern = regexp.MustCompile(`\bwith-interface (?:equals )?\{([^}]*)\}`)
)

type GuardRecord struct {
	VendorID   string
	ProductID  string
	Serial     string
	Hash       string
	PortPath   string
	Interfaces []string
}

type CommandUSBGuard struct {
	Executor commandexec.Executor
	Binary   string
}

func (g CommandUSBGuard) Hash(ctx context.Context, probe GuardProbe) (string, error) {
	if g.Executor == nil || !filepath.IsAbs(g.Binary) || filepath.Clean(g.Binary) != g.Binary {
		return "", errors.New("USBGuard command adapter is not configured")
	}
	result, err := g.Executor.Run(ctx, g.Binary, "list-devices")
	if err != nil {
		return "", errors.New("USBGuard device listing failed")
	}
	records, err := ParseUSBGuardRecords(result.Stdout)
	if err != nil {
		return "", err
	}
	probeInterfaces := append([]string(nil), probe.Interfaces...)
	for index := range probeInterfaces {
		probeInterfaces[index] = strings.ToLower(strings.TrimSpace(probeInterfaces[index]))
	}
	sort.Strings(probeInterfaces)
	matches := make([]GuardRecord, 0, 1)
	for _, record := range records {
		if strings.EqualFold(record.VendorID, probe.VendorID) &&
			strings.EqualFold(record.ProductID, probe.ProductID) &&
			record.Serial == probe.Serial &&
			record.PortPath == probe.PortPath &&
			equalStrings(record.Interfaces, probeInterfaces) {
			matches = append(matches, record)
		}
	}
	if len(matches) != 1 {
		return "", errors.New("USBGuard identity lookup was missing or ambiguous")
	}
	return matches[0].Hash, nil
}

func ParseUSBGuardRecords(data []byte) ([]GuardRecord, error) {
	if len(data) > commandexec.DefaultCaptureLimit || strings.IndexByte(string(data), 0) >= 0 {
		return nil, errors.New("USBGuard output is invalid")
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	records := make([]GuardRecord, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		id := guardIDPattern.FindStringSubmatch(line)
		hash := guardHashFieldPattern.FindStringSubmatch(line)
		port := guardPortFieldPattern.FindStringSubmatch(line)
		interfaces := guardInterfacePattern.FindStringSubmatch(line)
		if len(id) != 3 || len(hash) != 2 || len(port) != 2 || len(interfaces) != 2 {
			return nil, errors.New("USBGuard output record is incomplete")
		}
		serial := ""
		if match := guardSerialPattern.FindStringSubmatch(line); len(match) == 2 {
			serial = match[1]
		}
		interfaceFields := strings.Fields(interfaces[1])
		if len(interfaceFields) == 0 || len(interfaceFields) > 32 {
			return nil, errors.New("USBGuard interface set is invalid")
		}
		for index := range interfaceFields {
			interfaceFields[index] = strings.ToLower(interfaceFields[index])
			if !interfacePattern.MatchString(interfaceFields[index]) {
				return nil, errors.New("USBGuard interface descriptor is invalid")
			}
		}
		sort.Strings(interfaceFields)
		records = append(records, GuardRecord{
			VendorID: strings.ToLower(id[1]), ProductID: strings.ToLower(id[2]),
			Serial: serial, Hash: hash[1], PortPath: port[1], Interfaces: interfaceFields,
		})
		if len(records) > maximumUSBGuardRecords {
			return nil, errors.New("USBGuard record limit exceeded")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("USBGuard output exceeded its line limit")
	}
	return records, nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}
