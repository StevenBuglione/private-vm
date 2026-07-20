package usb

import (
	"bufio"
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/StevenBuglione/private-vm/internal/commandexec"
)

const maximumUSBGuardRecords = 256

var (
	guardIDPattern        = regexp.MustCompile(`\bid ([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4})(?:\s|$)`)
	guardSerialPattern    = regexp.MustCompile(`\bserial "([^"]*)"`)
	guardHashFieldPattern = regexp.MustCompile(`\bhash "([A-Za-z0-9+/=_-]{16,256})"`)
	guardPortFieldPattern = regexp.MustCompile(`\bvia-port "([0-9]+(?:-[0-9]+(?:\.[0-9]+)*)?)"`)
	guardInterfacePattern = regexp.MustCompile(`\bwith-interface (?:equals )?\{([^}]*)\}`)
	guardPrefixPattern    = regexp.MustCompile(`^([0-9]{1,10}):\s+(allow|block|reject)\s+`)
)

type GuardRecord struct {
	ID         uint32
	Policy     string
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
	record, err := g.lookup(ctx, probe)
	if err != nil {
		return "", err
	}
	return record.Hash, nil
}

func (g CommandUSBGuard) lookup(ctx context.Context, probe GuardProbe) (GuardRecord, error) {
	records, err := g.list(ctx)
	if err != nil {
		return GuardRecord{}, err
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
		return GuardRecord{}, errors.New("USBGuard identity lookup was missing or ambiguous")
	}
	return matches[0], nil
}

func (g CommandUSBGuard) list(ctx context.Context) ([]GuardRecord, error) {
	if g.Executor == nil || !filepath.IsAbs(g.Binary) || filepath.Clean(g.Binary) != g.Binary {
		return nil, errors.New("USBGuard command adapter is not configured")
	}
	operation, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	result, err := g.Executor.Run(operation, g.Binary, "list-devices")
	if err != nil {
		return nil, errors.New("USBGuard device listing failed")
	}
	return ParseUSBGuardRecords(result.Stdout)
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
		prefix := guardPrefixPattern.FindStringSubmatch(line)
		id := guardIDPattern.FindStringSubmatch(line)
		hash := guardHashFieldPattern.FindStringSubmatch(line)
		port := guardPortFieldPattern.FindStringSubmatch(line)
		interfaces := guardInterfacePattern.FindStringSubmatch(line)
		if len(prefix) != 3 || len(id) != 3 || len(hash) != 2 || len(port) != 2 || len(interfaces) != 2 {
			return nil, errors.New("USBGuard output record is incomplete")
		}
		numericID, err := strconv.ParseUint(prefix[1], 10, 32)
		if err != nil || numericID == 0 {
			return nil, errors.New("USBGuard output record identifier is invalid")
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
			ID: uint32(numericID), Policy: prefix[2],
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

// Acquire authorizes only the exact freshly observed USBGuard record. The
// command receives a numeric USBGuard record ID only; complete identity values
// never enter argv or the environment.
func (g CommandUSBGuard) Acquire(ctx context.Context, device Device) (DeviceClaim, error) {
	if err := validateSelectable(device); err != nil {
		return nil, err
	}
	probe := guardProbe(device.Identity)
	record, err := g.lookup(ctx, probe)
	if err != nil || record.Hash != device.Identity.USBGuardHash {
		return nil, errors.New("USBGuard exact identity revalidation failed")
	}
	handle := &commandUSBGuardClaim{guard: g, record: record, probe: probe, expectedHash: record.Hash}
	if err := g.mutate(ctx, "allow-device", record.ID); err != nil {
		// The command may have committed before its wait/output boundary failed.
		// Return the exact handle so ClaimManager's one cleanup owner blocks and
		// audits this record before releasing the reservation.
		return handle, err
	}
	handle.allowed = true
	current, err := g.lookup(ctx, probe)
	if err != nil || current.ID != record.ID || current.Hash != record.Hash || current.Policy != "allow" {
		return handle, errors.New("USBGuard claim verification failed")
	}
	return handle, nil
}

func (g CommandUSBGuard) mutate(ctx context.Context, operation string, id uint32) error {
	if operation != "allow-device" && operation != "block-device" {
		return errors.New("USBGuard operation is invalid")
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := g.Executor.Run(bounded, g.Binary, operation, strconv.FormatUint(uint64(id), 10)); err != nil {
		return errors.New("USBGuard policy transition failed")
	}
	return nil
}

type commandUSBGuardClaim struct {
	mu           sync.Mutex
	guard        CommandUSBGuard
	record       GuardRecord
	probe        GuardProbe
	expectedHash string
	allowed      bool
}

func (c *commandUSBGuardClaim) Release(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	records, err := c.guard.list(ctx)
	if err != nil {
		return err
	}
	current, present, changed := exactRecord(records, c.record, c.probe, c.expectedHash)
	if changed {
		return errors.New("USBGuard record identity changed before release")
	}
	if !present || current.Policy == "block" {
		c.allowed = false
		return nil
	}
	if current.Policy != "allow" {
		return errors.New("USBGuard claim has an unexpected policy state")
	}
	if err := c.guard.mutate(ctx, "block-device", c.record.ID); err != nil {
		return err
	}
	c.allowed = false
	return nil
}

func (c *commandUSBGuardClaim) AuditAbsent(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	records, err := c.guard.list(ctx)
	if err != nil {
		return err
	}
	current, present, changed := exactRecord(records, c.record, c.probe, c.expectedHash)
	if changed {
		return errors.New("USBGuard record identity changed during absence audit")
	}
	if !present || current.Policy == "block" {
		c.allowed = false
		return nil
	}
	return errors.New("USBGuard claim remains authorized")
}

func guardProbe(identity Identity) GuardProbe {
	identity = identity.normalized()
	return GuardProbe{VendorID: identity.VendorID, ProductID: identity.ProductID, Serial: identity.Serial, PortPath: identity.PortPath, Interfaces: append([]string(nil), identity.Interfaces...)}
}

func exactRecord(records []GuardRecord, expected GuardRecord, probe GuardProbe, hash string) (GuardRecord, bool, bool) {
	for _, record := range records {
		if record.ID != expected.ID {
			continue
		}
		matches := strings.EqualFold(record.VendorID, probe.VendorID) && strings.EqualFold(record.ProductID, probe.ProductID) && record.Serial == probe.Serial && record.PortPath == probe.PortPath && equalStrings(record.Interfaces, probe.Interfaces) && record.Hash == hash
		return record, matches, !matches
	}
	return GuardRecord{}, false, false
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
