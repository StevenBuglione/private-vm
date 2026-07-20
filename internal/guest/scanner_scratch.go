package guest

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"

	"github.com/StevenBuglione/private-vm/internal/scan"
	"golang.org/x/sys/unix"
)

type scannerScratchVerifier interface {
	Verify(context.Context) error
}

type scannerScratchEvidence struct {
	matches                  uint32
	filesystem, mountRoot    string
	options                  map[string]bool
	totalBytes               uint64
	rootUID, rootGID         uint32
	workerUID, workerGID     uint32
	rootMode, workerMode     uint32
	sameDevice, distinctNode bool
}

type scannerScratchCollector func(context.Context, productionScannerScratchVerifier) (scannerScratchEvidence, error)

type productionScannerScratchVerifier struct {
	mountRoot, workerRoot string
	maximumBytes          uint64
	workerUID, workerGID  uint32
	collect               scannerScratchCollector
}

func (verifier productionScannerScratchVerifier) Verify(ctx context.Context) error {
	if ctx == nil {
		return scannerScratchUnverified()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !filepath.IsAbs(verifier.mountRoot) || filepath.Clean(verifier.mountRoot) != verifier.mountRoot ||
		filepath.Dir(verifier.workerRoot) != verifier.mountRoot || filepath.Base(verifier.workerRoot) != "worker" ||
		verifier.maximumBytes == 0 || verifier.maximumBytes > maximumScannerScratchBytes || verifier.workerUID == 0 || verifier.workerGID == 0 {
		return scannerScratchUnverified()
	}
	collector := verifier.collect
	if collector == nil {
		collector = collectScannerScratchEvidence
	}
	evidence, err := collector(ctx, verifier)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return scannerScratchUnverified()
	}
	if evidence.matches != 1 || evidence.filesystem != "tmpfs" || evidence.mountRoot != "/" ||
		evidence.totalBytes == 0 || evidence.totalBytes > verifier.maximumBytes ||
		!evidence.options["rw"] || !evidence.options["nosuid"] || !evidence.options["nodev"] || !evidence.options["noexec"] ||
		evidence.options["ro"] || evidence.options["suid"] || evidence.options["dev"] || evidence.options["exec"] ||
		evidence.rootUID != 0 || evidence.rootGID != 0 || evidence.rootMode != 0o711 ||
		evidence.workerUID != verifier.workerUID || evidence.workerGID != verifier.workerGID || evidence.workerMode != 0o700 ||
		!evidence.sameDevice || !evidence.distinctNode {
		return scannerScratchUnverified()
	}
	return nil
}

func collectScannerScratchEvidence(ctx context.Context, verifier productionScannerScratchVerifier) (scannerScratchEvidence, error) {
	var evidence scannerScratchEvidence
	data, err := readBoundedPseudoFile("/proc/self/mountinfo", 1<<20)
	if err != nil {
		return evidence, err
	}
	defer clear(data)
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if err := ctx.Err(); err != nil {
			return evidence, err
		}
		fields := strings.Fields(string(line))
		if len(fields) < 6 || fields[4] != verifier.mountRoot {
			continue
		}
		evidence.matches++
		separator := slices.Index(fields, "-")
		if separator < 6 || separator+3 >= len(fields) {
			return evidence, errors.New("malformed mount evidence")
		}
		evidence.mountRoot = fields[3]
		evidence.filesystem = fields[separator+1]
		evidence.options = make(map[string]bool)
		for _, optionSet := range []string{fields[5], fields[separator+3]} {
			for _, option := range strings.Split(optionSet, ",") {
				evidence.options[option] = true
			}
		}
	}
	if evidence.matches != 1 {
		return evidence, nil
	}
	rootFD, err := unix.Open(verifier.mountRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return evidence, err
	}
	defer unix.Close(rootFD)
	workerFD, err := unix.Open(verifier.workerRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return evidence, err
	}
	defer unix.Close(workerFD)
	var rootStat, workerStat unix.Stat_t
	var filesystem unix.Statfs_t
	if unix.Fstat(rootFD, &rootStat) != nil || unix.Fstat(workerFD, &workerStat) != nil || unix.Fstatfs(rootFD, &filesystem) != nil || filesystem.Type != unix.TMPFS_MAGIC || filesystem.Bsize <= 0 {
		return evidence, errors.New("invalid scratch filesystem")
	}
	blockSize := uint64(filesystem.Bsize)
	blocks := uint64(filesystem.Blocks)
	if blocks > ^uint64(0)/blockSize {
		return evidence, errors.New("scratch capacity overflow")
	}
	evidence.totalBytes = blocks * blockSize
	evidence.rootUID, evidence.rootGID = rootStat.Uid, rootStat.Gid
	evidence.workerUID, evidence.workerGID = workerStat.Uid, workerStat.Gid
	evidence.rootMode, evidence.workerMode = rootStat.Mode&0o777, workerStat.Mode&0o777
	evidence.sameDevice = rootStat.Dev == workerStat.Dev
	evidence.distinctNode = rootStat.Ino != workerStat.Ino
	return evidence, nil
}

func scannerScratchUnverified() error {
	return &scan.Error{
		Code: "SCANNER_SCRATCH_UNVERIFIED", Message: "The scanner scratch filesystem is not safely bounded.",
		Remediation: "Destroy the scanner and relaunch the verified image with its private bounded tmpfs scratch mount.",
	}
}
