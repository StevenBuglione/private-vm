//go:build linux

package guest

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/StevenBuglione/private-vm/internal/secret"
	"github.com/StevenBuglione/private-vm/internal/transfer"
	"golang.org/x/sys/unix"
)

const (
	fixedExporterMapperName = "private-vm-export"
	fixedExporterOutputName = "approved-output"
	fixedExporterTempName   = ".approved-output.partial"
	maximumExporterSysfs    = 4096
	maximumExporterOutput   = 64 << 10
)

type exporterCommandRunner interface {
	Run(context.Context, io.Reader, string, ...string) error
}

type osExporterCommandRunner struct{}

func (osExporterCommandRunner) Run(ctx context.Context, stdin io.Reader, binary string, arguments ...string) error {
	if !cleanAbsolute(binary) {
		return errors.New("exporter command path is invalid")
	}
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Stdin = stdin
	command.Env = []string{"LC_ALL=C", "PATH=/run/current-system/sw/bin"}
	stdout := &boundedExporterBuffer{limit: maximumExporterOutput}
	stderr := &boundedExporterBuffer{limit: maximumExporterOutput}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil || stdout.exceeded || stderr.exceeded {
		return errors.New("fixed exporter command failed")
	}
	return nil
}

type boundedExporterBuffer struct {
	data     []byte
	limit    int
	exceeded bool
}

func (buffer *boundedExporterBuffer) Write(value []byte) (int, error) {
	remaining := buffer.limit - len(buffer.data)
	if remaining < len(value) {
		if remaining > 0 {
			buffer.data = append(buffer.data, value[:remaining]...)
		}
		buffer.exceeded = true
		return len(value), nil
	}
	buffer.data = append(buffer.data, value...)
	return len(value), nil
}

type fixedExporterPaths struct {
	USBRoot     string
	BlockRoot   string
	DeviceRoot  string
	NetworkRoot string
	MountInfo   string
	MountPoint  string
	MapperPath  string
	Cryptsetup  string
	MkfsExt4    string
	Mount       string
	Umount      string
	Wipefs      string
	Blkid       string
}

type fixedExporterAdapter struct {
	paths              fixedExporterPaths
	runner             exporterCommandRunner
	filesystemVerifier func(string) error
	device             string
	expected           ExporterDeviceExpectation
	mounted            bool
	mapperOpen         bool
	writer             *fixedExporterWriter
}

// NewFixedExporterAdapter composes the exporter image's only destructive
// backend. Every path and tool is fixed by the verified image; RPC callers can
// supply identity evidence and bytes, but never a device, command, filename,
// mount target, filesystem, option, or mapper name.
func NewFixedExporterAdapter() (ExporterAdapter, error) {
	tool := func(name string) (string, error) {
		path, err := exec.LookPath(name)
		if err != nil {
			return "", errors.New("required exporter tool is unavailable")
		}
		path, err = filepath.Abs(path)
		if err != nil || !cleanAbsolute(path) || filepath.Base(path) != name {
			return "", errors.New("required exporter tool identity is invalid")
		}
		return path, nil
	}
	cryptsetup, err := tool("cryptsetup")
	if err != nil {
		return nil, err
	}
	mkfs, err := tool("mkfs.ext4")
	if err != nil {
		return nil, err
	}
	mount, err := tool("mount")
	if err != nil {
		return nil, err
	}
	umount, err := tool("umount")
	if err != nil {
		return nil, err
	}
	wipefs, err := tool("wipefs")
	if err != nil {
		return nil, err
	}
	blkid, err := tool("blkid")
	if err != nil {
		return nil, err
	}
	return newFixedExporterAdapter(fixedExporterPaths{
		USBRoot: "/sys/bus/usb/devices", BlockRoot: "/sys/class/block", DeviceRoot: "/dev",
		NetworkRoot: "/sys/class/net", MountInfo: "/proc/self/mountinfo",
		MountPoint: "/run/private-vm/export", MapperPath: "/dev/mapper/" + fixedExporterMapperName,
		Cryptsetup: cryptsetup, MkfsExt4: mkfs, Mount: mount, Umount: umount, Wipefs: wipefs, Blkid: blkid,
	}, osExporterCommandRunner{})
}

func newFixedExporterAdapter(paths fixedExporterPaths, runner exporterCommandRunner) (*fixedExporterAdapter, error) {
	for _, path := range []string{paths.USBRoot, paths.BlockRoot, paths.DeviceRoot, paths.NetworkRoot, paths.MountInfo, paths.MountPoint, paths.MapperPath,
		paths.Cryptsetup, paths.MkfsExt4, paths.Mount, paths.Umount, paths.Wipefs, paths.Blkid} {
		if !cleanAbsolute(path) {
			return nil, errors.New("fixed exporter path is invalid")
		}
	}
	if runner == nil || filepath.Base(paths.MapperPath) != fixedExporterMapperName {
		return nil, errors.New("fixed exporter adapter is incomplete")
	}
	return &fixedExporterAdapter{paths: paths, runner: runner, filesystemVerifier: verifyExporterExt4}, nil
}

func (adapter *fixedExporterAdapter) Inspect(ctx context.Context, expected ExporterDeviceExpectation) (ExporterDeviceEvidence, error) {
	if err := expected.validate(); err != nil {
		return ExporterDeviceEvidence{}, err
	}
	if err := onlyLoopbackNetwork(adapter.paths.NetworkRoot); err != nil {
		return ExporterDeviceEvidence{}, err
	}
	devices, err := discoverExporterDevices(ctx, adapter.paths)
	if err != nil || len(devices) != 1 {
		return ExporterDeviceEvidence{}, errors.New("exporter requires exactly one USB mass-storage device")
	}
	device := devices[0]
	if device.VendorID != expected.VendorID || device.ProductID != expected.ProductID || device.Serial != expected.Serial || device.Capacity != expected.Capacity {
		return ExporterDeviceEvidence{}, errors.New("exporter USB identity does not match")
	}
	if device.Mounted || device.HostFilesystem {
		return ExporterDeviceEvidence{}, errors.New("exporter USB is already mounted or aliases the guest root")
	}
	adapter.device, adapter.expected = device.Path, expected
	return ExporterDeviceEvidence{Expectation: expected, NoNetwork: true, HostPathAbsent: true, SingleDevice: true, MassStorageOnly: true}, nil
}

func (adapter *fixedExporterAdapter) Prepare(ctx context.Context, passphrase *secret.Bytes) (ExporterPrepareEvidence, error) {
	if adapter.device == "" || passphrase == nil || adapter.mounted || adapter.mapperOpen {
		return ExporterPrepareEvidence{}, errors.New("exporter is not ready for preparation")
	}
	if err := os.MkdirAll(adapter.paths.MountPoint, 0o700); err != nil {
		return ExporterPrepareEvidence{}, errors.New("create fixed exporter mount point")
	}
	if err := adapter.runner.Run(ctx, nil, adapter.paths.Wipefs, "--all", adapter.device); err != nil {
		return ExporterPrepareEvidence{}, err
	}
	if err := passphrase.WithReader(func(reader io.Reader) error {
		return adapter.runner.Run(ctx, reader, adapter.paths.Cryptsetup, "luksFormat", "--type", "luks2", "--batch-mode", "--key-file", "-", adapter.device)
	}); err != nil {
		return ExporterPrepareEvidence{}, errors.New("LUKS2 preparation failed")
	}
	if err := passphrase.WithReader(func(reader io.Reader) error {
		return adapter.runner.Run(ctx, reader, adapter.paths.Cryptsetup, "open", "--type", "luks2", "--key-file", "-", adapter.device, fixedExporterMapperName)
	}); err != nil {
		return ExporterPrepareEvidence{}, errors.New("LUKS2 open failed")
	}
	adapter.mapperOpen = true
	if err := adapter.runner.Run(ctx, nil, adapter.paths.MkfsExt4, "-F", "-L", "PRIVATE_VM_EXPORT", adapter.paths.MapperPath); err != nil {
		return ExporterPrepareEvidence{}, err
	}
	if err := adapter.runner.Run(ctx, nil, adapter.paths.Blkid, "-p", "-s", "TYPE", "-o", "value", adapter.paths.MapperPath); err != nil {
		return ExporterPrepareEvidence{}, err
	}
	if err := adapter.runner.Run(ctx, nil, adapter.paths.Mount, "-t", "ext4", "-o", "nodev,nosuid,noexec", adapter.paths.MapperPath, adapter.paths.MountPoint); err != nil {
		return ExporterPrepareEvidence{}, err
	}
	adapter.mounted = true
	if adapter.filesystemVerifier == nil || adapter.filesystemVerifier(adapter.paths.MountPoint) != nil {
		return ExporterPrepareEvidence{}, errors.New("fixed exporter filesystem verification failed")
	}
	return ExporterPrepareEvidence{IdentityVerified: true, LUKS2: true, Ext4: true, Mounted: true}, nil
}

func (adapter *fixedExporterAdapter) BeginWrite(_ context.Context, header transfer.Header, transferID string) (ExporterWriter, error) {
	if !adapter.mounted || adapter.writer != nil || !exporterTransferPattern.MatchString(transferID) {
		return nil, errors.New("fixed exporter writer is unavailable")
	}
	partial := filepath.Join(adapter.paths.MountPoint, fixedExporterTempName)
	final := filepath.Join(adapter.paths.MountPoint, fixedExporterOutputName)
	if err := os.Remove(partial); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, errors.New("remove stale exporter partial file")
	}
	if err := os.Remove(final); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, errors.New("remove previous exporter output")
	}
	file, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("create fixed exporter output")
	}
	writer := &fixedExporterWriter{adapter: adapter, file: file, partial: partial, final: final, expectedSize: header.Size, hash: sha256.New()}
	adapter.writer = writer
	return writer, nil
}

func (adapter *fixedExporterAdapter) Reread(ctx context.Context, transferID string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	if !adapter.mounted || !exporterTransferPattern.MatchString(transferID) {
		return digest, errors.New("fixed exporter reread is unavailable")
	}
	file, err := os.OpenFile(filepath.Join(adapter.paths.MountPoint, fixedExporterOutputName), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return digest, errors.New("open fixed exporter output")
	}
	defer file.Close()
	hash := sha256.New()
	buffer := make([]byte, transfer.DefaultMaxChunk)
	defer clear(buffer)
	for {
		if err := ctx.Err(); err != nil {
			return digest, err
		}
		n, readErr := file.Read(buffer)
		if n > 0 {
			_, _ = hash.Write(buffer[:n])
			clear(buffer[:n])
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return digest, errors.New("reread fixed exporter output")
		}
	}
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func (adapter *fixedExporterAdapter) Finalize(ctx context.Context) (ExporterFinalizeEvidence, error) {
	if !adapter.mounted || !adapter.mapperOpen || adapter.writer != nil {
		return ExporterFinalizeEvidence{}, errors.New("fixed exporter is not ready to finalize")
	}
	if err := adapter.runner.Run(ctx, nil, adapter.paths.Umount, adapter.paths.MountPoint); err != nil {
		return ExporterFinalizeEvidence{}, err
	}
	adapter.mounted = false
	if err := adapter.runner.Run(ctx, nil, adapter.paths.Cryptsetup, "close", fixedExporterMapperName); err != nil {
		return ExporterFinalizeEvidence{Unmounted: true}, err
	}
	adapter.mapperOpen = false
	return ExporterFinalizeEvidence{Unmounted: true, LUKSClosed: true}, nil
}

func (adapter *fixedExporterAdapter) Cleanup(ctx context.Context) error {
	var result error
	if adapter.writer != nil {
		result = errors.Join(result, adapter.writer.Abort(ctx))
	}
	if adapter.mounted {
		if err := adapter.runner.Run(ctx, nil, adapter.paths.Umount, adapter.paths.MountPoint); err != nil {
			result = errors.Join(result, err)
		} else {
			adapter.mounted = false
		}
	}
	if adapter.mapperOpen && !adapter.mounted {
		if err := adapter.runner.Run(ctx, nil, adapter.paths.Cryptsetup, "close", fixedExporterMapperName); err != nil {
			result = errors.Join(result, err)
		} else {
			adapter.mapperOpen = false
		}
	}
	return result
}

type fixedExporterWriter struct {
	adapter      *fixedExporterAdapter
	file         *os.File
	partial      string
	final        string
	expectedSize uint64
	written      uint64
	hash         hashWriter
	closed       bool
}

type hashWriter interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

func (writer *fixedExporterWriter) WriteChunk(ctx context.Context, _ uint64, data []byte) error {
	if writer.closed || writer.file == nil || writer.written > writer.expectedSize || uint64(len(data)) > writer.expectedSize-writer.written {
		return errors.New("fixed exporter write bound exceeded")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	n, err := writer.file.Write(data)
	if err != nil || n != len(data) {
		return errors.New("write fixed exporter output")
	}
	_, _ = writer.hash.Write(data)
	writer.written += uint64(n)
	return nil
}

func (writer *fixedExporterWriter) Commit(_ context.Context, size uint64, expected [sha256.Size]byte) (ExporterWriteEvidence, error) {
	var actual [sha256.Size]byte
	copy(actual[:], writer.hash.Sum(nil))
	if writer.closed || size != writer.expectedSize || writer.written != size || actual != expected {
		return ExporterWriteEvidence{}, errors.New("fixed exporter output digest mismatch")
	}
	if err := writer.file.Sync(); err != nil {
		return ExporterWriteEvidence{}, errors.New("sync fixed exporter output")
	}
	if err := writer.file.Close(); err != nil {
		return ExporterWriteEvidence{}, errors.New("close fixed exporter output")
	}
	writer.file = nil
	if err := os.Rename(writer.partial, writer.final); err != nil {
		return ExporterWriteEvidence{}, errors.New("commit fixed exporter output")
	}
	directory, err := os.Open(writer.adapter.paths.MountPoint)
	if err != nil {
		return ExporterWriteEvidence{}, errors.New("open fixed exporter directory")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return ExporterWriteEvidence{}, errors.New("sync fixed exporter directory")
	}
	if err := unix.Syncfs(int(directory.Fd())); err != nil {
		return ExporterWriteEvidence{}, errors.New("sync fixed exporter filesystem")
	}
	writer.closed = true
	writer.adapter.writer = nil
	return ExporterWriteEvidence{ReceiverDigest: actual, FileSynced: true, FilesystemSynced: true, AtomicRename: true}, nil
}

func (writer *fixedExporterWriter) Abort(_ context.Context) error {
	if writer.file != nil {
		_ = writer.file.Close()
		writer.file = nil
	}
	err := os.Remove(writer.partial)
	if errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	writer.closed = true
	if writer.adapter.writer == writer {
		writer.adapter.writer = nil
	}
	return err
}

type exporterDevice struct {
	Path, VendorID, ProductID, Serial string
	Capacity                          uint64
	Mounted, HostFilesystem           bool
}

func discoverExporterDevices(ctx context.Context, paths fixedExporterPaths) ([]exporterDevice, error) {
	entries, err := os.ReadDir(paths.USBRoot)
	if err != nil || len(entries) > maximumExporterSysfs {
		return nil, errors.New("read exporter USB inventory")
	}
	mounts, err := exporterMountDevices(paths.MountInfo)
	if err != nil {
		return nil, err
	}
	devices := make([]exporterDevice, 0, 1)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if strings.Contains(entry.Name(), ":") || !usbPortName(entry.Name()) {
			continue
		}
		root, err := filepath.EvalSymlinks(filepath.Join(paths.USBRoot, entry.Name()))
		if err != nil {
			continue
		}
		vendor, err := smallExporterValue(filepath.Join(root, "idVendor"))
		if err != nil {
			continue
		}
		product, err := smallExporterValue(filepath.Join(root, "idProduct"))
		if err != nil {
			continue
		}
		serial, _ := smallExporterValue(filepath.Join(root, "serial"))
		massStorage, err := exporterMassStorageOnly(paths.USBRoot, entry.Name())
		if err != nil || !massStorage {
			continue
		}
		blocks, err := exporterBlockNames(root)
		if err != nil || len(blocks) != 1 {
			continue
		}
		block := blocks[0]
		sectors, err := exporterUint(filepath.Join(paths.BlockRoot, block, "size"))
		if err != nil || sectors == 0 || sectors > ^uint64(0)/512 {
			return nil, errors.New("exporter USB capacity is invalid")
		}
		deviceNumbers, err := exporterBlockDeviceNumbers(paths.BlockRoot, root)
		if err != nil {
			return nil, err
		}
		mounted, host := false, false
		for deviceNumber, mountPoints := range mounts {
			if _, ok := deviceNumbers[deviceNumber]; !ok {
				continue
			}
			mounted = true
			for _, point := range mountPoints {
				if point == "/" || point == "/boot" || strings.HasPrefix(point, "/boot/") || point == "/nix" || strings.HasPrefix(point, "/nix/") {
					host = true
				}
			}
		}
		devicePath := filepath.Join(paths.DeviceRoot, block)
		var stat unix.Stat_t
		if err := unix.Stat(devicePath, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFBLK {
			return nil, errors.New("exporter USB block device identity is invalid")
		}
		devices = append(devices, exporterDevice{Path: devicePath, VendorID: strings.ToLower(vendor), ProductID: strings.ToLower(product), Serial: serial, Capacity: sectors * 512, Mounted: mounted, HostFilesystem: host})
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].Path < devices[j].Path })
	return devices, nil
}

func onlyLoopbackNetwork(root string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return errors.New("read exporter network inventory")
	}
	for _, entry := range entries {
		if entry.Name() != "lo" {
			return errors.New("exporter has a forbidden network interface")
		}
	}
	return nil
}

func exporterMassStorageOnly(root, name string) (bool, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return false, err
	}
	count := 0
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), name+":") {
			continue
		}
		resolved, err := filepath.EvalSymlinks(filepath.Join(root, entry.Name()))
		if err != nil {
			return false, err
		}
		class, err := smallExporterValue(filepath.Join(resolved, "bInterfaceClass"))
		if err != nil || !strings.EqualFold(class, "08") {
			return false, err
		}
		count++
	}
	return count > 0 && count <= 32, nil
}

func exporterBlockNames(root string) ([]string, error) {
	result := make(map[string]struct{})
	count := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		count++
		if count > maximumExporterSysfs {
			return errors.New("exporter sysfs traversal limit exceeded")
		}
		if entry.IsDir() && filepath.Base(filepath.Dir(path)) == "block" {
			result[entry.Name()] = struct{}{}
			return filepath.SkipDir
		}
		return nil
	})
	values := make([]string, 0, len(result))
	for value := range result {
		values = append(values, value)
	}
	sort.Strings(values)
	return values, err
}

func exporterBlockDeviceNumbers(blockRoot, usbRoot string) (map[string]struct{}, error) {
	entries, err := os.ReadDir(blockRoot)
	if err != nil {
		return nil, err
	}
	result := make(map[string]struct{})
	for _, entry := range entries {
		resolved, err := filepath.EvalSymlinks(filepath.Join(blockRoot, entry.Name()))
		if err != nil || (resolved != usbRoot && !strings.HasPrefix(resolved, usbRoot+string(filepath.Separator))) {
			continue
		}
		value, err := smallExporterValue(filepath.Join(blockRoot, entry.Name(), "dev"))
		if err == nil {
			result[value] = struct{}{}
		}
	}
	return result, nil
}

func exporterMountDevices(path string) (map[string][]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open exporter mount inventory")
	}
	defer file.Close()
	result := make(map[string][]string)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			return nil, errors.New("exporter mount inventory is malformed")
		}
		result[fields[2]] = append(result[fields[2]], fields[4])
		if len(result) > maximumExporterSysfs {
			return nil, errors.New("exporter mount inventory exceeded its bound")
		}
	}
	return result, scanner.Err()
}

func smallExporterValue(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("read exporter sysfs value")
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(value) == 0 || len(value) > 4096 || strings.IndexByte(string(value), 0) >= 0 {
		return "", errors.New("read exporter sysfs value")
	}
	return strings.TrimSpace(string(value)), nil
}

func exporterUint(path string) (uint64, error) {
	value, err := smallExporterValue(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(value, 10, 64)
}

func usbPortName(value string) bool {
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "/\x00\r\n") {
		return false
	}
	parts := strings.Split(value, "-")
	if len(parts) != 2 {
		return false
	}
	if _, err := strconv.ParseUint(parts[0], 10, 16); err != nil {
		return false
	}
	for _, component := range strings.Split(parts[1], ".") {
		if _, err := strconv.ParseUint(component, 10, 16); err != nil {
			return false
		}
	}
	return true
}

func cleanAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func verifyExporterExt4(path string) error {
	var filesystem unix.Statfs_t
	if err := unix.Statfs(path, &filesystem); err != nil {
		return err
	}
	if filesystem.Type != unix.EXT4_SUPER_MAGIC {
		return errors.New("fixed exporter mount is not ext4")
	}
	return nil
}

var _ ExporterAdapter = (*fixedExporterAdapter)(nil)
