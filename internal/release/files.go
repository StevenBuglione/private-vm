package release

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func canonicalJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func decodeClosed(data []byte, destination any) error {
	if len(data) == 0 || int64(len(data)) > MaximumEvidenceBytes {
		return errors.New("release evidence is outside its byte bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("release evidence is malformed")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return errors.New("release evidence contains trailing data")
	}
	return nil
}

func digestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func hashFile(ctx context.Context, path string, maximum int64) (int64, string, error) {
	file, info, err := openRegular(path, maximum)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()
	hash := sha256.New()
	buffer := make([]byte, 1<<20)
	var size int64
	for {
		if err := ctx.Err(); err != nil {
			return 0, "", err
		}
		count, readErr := file.Read(buffer)
		if count > 0 {
			size += int64(count)
			if size > maximum {
				return 0, "", errors.New("release file exceeds its byte bound")
			}
			_, _ = hash.Write(buffer[:count])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return 0, "", errors.New("release file could not be read")
		}
	}
	if size != info.Size() {
		return 0, "", errors.New("release file changed while hashing")
	}
	return size, "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func openRegular(path string, maximum int64) (*os.File, os.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, nil, errors.New("release path is not canonical and absolute")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, errors.New("release file could not be opened safely")
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	info, statErr := file.Stat()
	if statErr != nil || info == nil {
		_ = file.Close()
		return nil, nil, errors.Join(statErr, errors.New("release file could not be inspected"))
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		_ = file.Close()
		return nil, nil, errors.New("release file owner evidence is unavailable")
	}
	uid := uint32(stat.Uid)
	trustedNixOutput := uid == 0 && strings.HasPrefix(path, "/nix/store/")
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum || info.Mode()&0o022 != 0 || (uid != uint32(os.Geteuid()) && !trustedNixOutput) {
		_ = file.Close()
		return nil, nil, errors.Join(statErr, errors.New("release file type, owner, mode or size is unsafe"))
	}
	return file, info, nil
}

func copyVerified(ctx context.Context, source, destination string, maximum int64) (int64, string, error) {
	input, info, err := openRegular(source, maximum)
	if err != nil {
		return 0, "", err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, "", errors.New("release output could not be created exclusively")
	}
	ok := false
	defer func() {
		_ = output.Close()
		if !ok {
			_ = os.Remove(destination)
		}
	}()
	hash := sha256.New()
	written, err := copyContext(ctx, io.MultiWriter(output, hash), io.LimitReader(input, maximum+1))
	if err != nil || written != info.Size() || written > maximum {
		return 0, "", errors.New("release artifact copy was incomplete")
	}
	if err := output.Sync(); err != nil {
		return 0, "", errors.New("release artifact could not be synchronized")
	}
	if err := output.Close(); err != nil {
		return 0, "", errors.New("release artifact could not be closed")
	}
	ok = true
	return written, "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func copyContext(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, 1<<20)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		count, readErr := source.Read(buffer)
		if count > 0 {
			written, writeErr := destination.Write(buffer[:count])
			total += int64(written)
			if writeErr != nil || written != count {
				return total, errors.New("release stream write failed")
			}
		}
		if readErr == io.EOF {
			return total, nil
		}
		if readErr != nil {
			return total, errors.New("release stream read failed")
		}
	}
}

func writeExclusive(path string, data []byte) error {
	if int64(len(data)) > MaximumEvidenceBytes {
		return errors.New("release evidence exceeds its byte bound")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("release evidence could not be created exclusively")
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return errors.New("release evidence could not be written")
	}
	if err := file.Sync(); err != nil {
		return errors.New("release evidence could not be synchronized")
	}
	if err := file.Close(); err != nil {
		return errors.New("release evidence could not be closed")
	}
	ok = true
	return nil
}

func readBounded(path string, maximum int64) ([]byte, error) {
	file, info, err := openRegular(path, maximum)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) != info.Size() || int64(len(data)) > maximum {
		return nil, errors.New("release evidence could not be read completely")
	}
	return data, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil && !errors.Is(err, unix.EINVAL) {
		return err
	}
	return nil
}

func removeOwnedTree(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return errors.New("release cleanup root is unsafe")
	}
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) || uint32(info.Sys().(*syscall.Stat_t).Uid) != uint32(os.Geteuid()) {
			return errors.Join(err, errors.New("release cleanup found an unsafe entry"))
		}
		mode := os.FileMode(0o600)
		if info.IsDir() {
			mode = 0o700
		}
		return os.Chmod(path, mode)
	})
	if err != nil {
		return err
	}
	if err := os.RemoveAll(root); err != nil {
		return err
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		return errors.New("release cleanup did not prove absence")
	}
	return nil
}

func cleanName(value string) bool {
	return value != "" && filepath.Base(value) == value && !strings.ContainsAny(value, "\\/\x00")
}
