package transfer

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// Source is one already-opened trusted host file. The path is never reopened:
// preflight hashing and transfer use the same no-follow descriptor.
type Source struct {
	file   *os.File
	parent *os.File
	header Header
	info   os.FileInfo
	used   bool
}

func OpenSource(ctx context.Context, path string, maximum uint64) (*Source, error) {
	absolute, err := filepath.Abs(path)
	if err != nil || filepath.Clean(absolute) != absolute {
		return nil, errors.New("source path is not canonical")
	}
	file, parent, err := openSourceNoFollow(absolute)
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = file.Close()
			_ = parent.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || uint64(info.Size()) > maximum {
		return nil, errors.New("source must be one bounded regular file")
	}
	header := Header{Name: filepath.Base(absolute), Size: uint64(info.Size())}
	if err := header.Validate(maximum); err != nil {
		return nil, err
	}
	digest, err := hashOpenFile(ctx, file, maximum)
	if err != nil {
		return nil, err
	}
	header.SHA256 = digest
	after, err := file.Stat()
	if err != nil || !sameFileState(info, after) {
		return nil, errors.New("source changed during preflight hashing")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	failed = false
	return &Source{file: file, parent: parent, header: header, info: info}, nil
}

func (source *Source) Header() Header { return source.header }

// Stream emits one bounded sequence and proves the bytes still match the
// preflight descriptor. A Source is intentionally single-use.
func (source *Source) Stream(ctx context.Context, send func(sequence uint64, data []byte) error) error {
	if source == nil || source.file == nil || source.used || send == nil {
		return errors.New("source stream is unavailable")
	}
	source.used = true
	hash := sha256.New()
	buffer := make([]byte, DefaultMaxChunk)
	var sequence, total uint64
	for {
		if err := ctx.Err(); err != nil {
			clear(buffer)
			return err
		}
		count, err := source.file.Read(buffer)
		if count > 0 {
			if uint64(count) > source.header.Size-total {
				clear(buffer)
				return errors.New("source exceeds its declared size")
			}
			total += uint64(count)
			_, _ = hash.Write(buffer[:count])
			data := append([]byte(nil), buffer[:count]...)
			sendErr := send(sequence, data)
			clear(data)
			if sendErr != nil {
				clear(buffer)
				return sendErr
			}
			sequence++
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			clear(buffer)
			return err
		}
	}
	clear(buffer)
	after, err := source.file.Stat()
	if err != nil || !sameFileState(source.info, after) || total != source.header.Size || !equal(hash.Sum(nil), source.header.SHA256[:]) {
		return errors.New("source changed during transfer")
	}
	return nil
}

func (source *Source) Close() error {
	if source == nil {
		return nil
	}
	var fileErr, parentErr error
	if source.file != nil {
		fileErr = source.file.Close()
	}
	if source.parent != nil {
		parentErr = source.parent.Close()
	}
	source.file = nil
	source.parent = nil
	return errors.Join(fileErr, parentErr)
}

func hashOpenFile(ctx context.Context, file *os.File, maximum uint64) ([sha256.Size]byte, error) {
	hash := sha256.New()
	buffer := make([]byte, DefaultMaxChunk)
	var total uint64
	for {
		if err := ctx.Err(); err != nil {
			clear(buffer)
			return [sha256.Size]byte{}, err
		}
		count, err := file.Read(buffer)
		if count > 0 {
			if uint64(count) > maximum-total {
				clear(buffer)
				return [sha256.Size]byte{}, errors.New("source exceeds bound")
			}
			total += uint64(count)
			_, _ = hash.Write(buffer[:count])
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			clear(buffer)
			return [sha256.Size]byte{}, err
		}
	}
	clear(buffer)
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func sameFileState(before, after os.FileInfo) bool {
	return os.SameFile(before, after) && before.Mode() == after.Mode() && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}
