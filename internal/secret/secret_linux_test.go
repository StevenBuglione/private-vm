//go:build linux

package secret

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestLinuxMemfdIsSealedReadOnlyIndependentAndNoDump(t *testing.T) {
	value, err := New([]byte(publicFixture))
	if err != nil {
		t.Fatal(err)
	}
	defer value.Destroy()
	if value.state.fd < 0 || !value.state.mapped {
		t.Skip("kernel does not provide memfd_create")
	}
	first, err := value.DupFile()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := value.DupFile()
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	prefix := make([]byte, 3)
	if _, err := io.ReadFull(first, prefix); err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(second)
	if err != nil || string(actual) != publicFixture {
		t.Fatalf("second descriptor did not start at zero: bytes=%d error=%v", len(actual), err)
	}
	clear(actual)
	if _, err := first.Write([]byte("x")); err == nil {
		t.Fatal("exported descriptor was writable")
	}
	if err := unix.Ftruncate(int(first.Fd()), 1); err == nil {
		t.Fatal("exported descriptor permitted truncation")
	}
	flags, err := unix.FcntlInt(first.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("duplicate is not CLOEXEC: flags=%x error=%v", flags, err)
	}
	seals, err := unix.FcntlInt(first.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&requiredSeals != requiredSeals {
		t.Fatalf("memfd seals=%x error=%v", seals, err)
	}
	info, err := first.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("memfd mode=%v error=%v", info.Mode().Perm(), err)
	}
	if !mappingIsDontDump(t, value.state.value) {
		t.Fatal("secret mapping is not excluded from core dumps")
	}
}

func TestDestroyZeroesLiveMemfdBeforeRelease(t *testing.T) {
	value, err := New([]byte(publicFixture))
	if err != nil {
		t.Fatal(err)
	}
	if value.state.fd < 0 {
		t.Skip("kernel does not provide memfd_create")
	}
	duplicate, err := value.DupFile()
	if err != nil {
		t.Fatal(err)
	}
	defer duplicate.Close()
	value.Destroy()
	if _, err := duplicate.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	actual := make([]byte, len(publicFixture))
	if _, err := io.ReadFull(duplicate, actual); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, make([]byte, len(actual))) {
		t.Fatal("destroy did not zero the current mapped bytes")
	}
}

func TestLinuxMemfdFailureIsFailClosedAndMlockIsBestEffort(t *testing.T) {
	originalCreate, originalLock := createMemfd, lockMemory
	t.Cleanup(func() { createMemfd, lockMemory = originalCreate, originalLock })
	createMemfd = func(string, int) (int, error) { return -1, unix.EPERM }
	if _, err := New([]byte(publicFixture)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("supported-kernel failure error = %v", err)
	}
	createMemfd = originalCreate
	lockMemory = func([]byte) error { return unix.EPERM }
	value, err := New([]byte(publicFixture))
	if err != nil {
		t.Fatalf("best-effort mlock failure blocked allocation: %v", err)
	}
	defer value.Destroy()
	if value.state.locked {
		t.Fatal("failed mlock was recorded as successful")
	}
}

func TestLinuxPostCopySetupFailureZeroesBacking(t *testing.T) {
	originalAddSeals := addSeals
	t.Cleanup(func() { addSeals = originalAddSeals })
	var retained *os.File
	addSeals = func(fd int) (int, error) {
		duplicate, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return 0, err
		}
		retained = os.NewFile(uintptr(duplicate), "failed-secret-backing")
		if retained == nil {
			_ = unix.Close(duplicate)
			return 0, unix.EBADF
		}
		return 0, unix.EPERM
	}
	if _, err := New([]byte(publicFixture)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("post-copy setup error = %v", err)
	}
	if retained == nil {
		t.Fatal("failure hook did not retain the backing")
	}
	defer retained.Close()
	actual, err := io.ReadAll(io.LimitReader(retained, int64(len(publicFixture)+1)))
	if err != nil {
		t.Fatal(err)
	}
	if len(actual) != len(publicFixture) || !bytes.Equal(actual, make([]byte, len(actual))) {
		t.Fatal("post-copy setup failure did not zero the backing")
	}
}

func TestLinuxENOSYSFallbackCannotExportDescriptor(t *testing.T) {
	originalCreate := createMemfd
	t.Cleanup(func() { createMemfd = originalCreate })
	createMemfd = func(string, int) (int, error) { return -1, unix.ENOSYS }
	value, err := New([]byte(publicFixture))
	if err != nil {
		t.Fatal(err)
	}
	defer value.Destroy()
	if _, err := value.DupFile(); !errors.Is(err, ErrNotMemfd) {
		t.Fatalf("fallback descriptor error = %v", err)
	}
}

func TestSecretInheritedFDIsAbsentFromArgvAndEnvironment(t *testing.T) {
	if os.Getenv("PRIVATE_VM_SECRET_HELPER") == "1" {
		t.Fatal("helper must run through TestSecretFDHelper")
	}
	value, err := New([]byte(publicFixture))
	if err != nil {
		t.Fatal(err)
	}
	defer value.Destroy()
	secretFile, err := value.DupFile()
	if err != nil {
		t.Fatal(err)
	}
	defer secretFile.Close()
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readyRead.Close()
	releaseRead, releaseWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer releaseWrite.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSecretFDHelper$")
	command.Env = []string{"PRIVATE_VM_SECRET_HELPER=1"}
	command.ExtraFiles = []*os.File{secretFile, readyWrite, releaseRead}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = readyWrite.Close()
	_ = releaseRead.Close()
	waited := false
	defer func() {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	ready := make([]byte, 1)
	if _, err := io.ReadFull(readyRead, ready); err != nil {
		t.Fatal("secret FD helper did not become ready")
	}
	processDirectory := "/proc/" + strconv.Itoa(command.Process.Pid)
	cmdline, err := os.ReadFile(processDirectory + "/cmdline")
	if err != nil {
		t.Fatal(err)
	}
	environ, err := os.ReadFile(processDirectory + "/environ")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cmdline, []byte(publicFixture)) || bytes.Contains(environ, []byte(publicFixture)) {
		t.Fatal("secret fixture appeared in child argv or environment")
	}
	if _, err := releaseWrite.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	waited = true
}

func TestSecretFDHelper(t *testing.T) {
	if os.Getenv("PRIVATE_VM_SECRET_HELPER") != "1" {
		return
	}
	secretFile := os.NewFile(3, "inherited-secret")
	ready := os.NewFile(4, "ready")
	release := os.NewFile(5, "release")
	if secretFile == nil || ready == nil || release == nil {
		os.Exit(2)
	}
	actual, err := io.ReadAll(io.LimitReader(secretFile, int64(len(publicFixture)+1)))
	if err != nil || string(actual) != publicFixture {
		clear(actual)
		os.Exit(3)
	}
	clear(actual)
	if _, err := ready.Write([]byte{1}); err != nil {
		os.Exit(4)
	}
	if _, err := io.ReadFull(release, make([]byte, 1)); err != nil {
		os.Exit(5)
	}
}

func mappingIsDontDump(t *testing.T, value []byte) bool {
	t.Helper()
	if len(value) == 0 {
		return false
	}
	address := uintptr(unsafe.Pointer(&value[0]))
	data, err := os.ReadFile("/proc/self/smaps")
	if err != nil {
		t.Fatal(err)
	}
	containsAddress := false
	for _, line := range strings.Split(string(data), "\n") {
		var start, end uintptr
		if _, scanErr := fmt.Sscanf(line, "%x-%x", &start, &end); scanErr == nil {
			containsAddress = address >= start && address < end
			continue
		}
		if containsAddress && strings.HasPrefix(line, "VmFlags:") {
			return strings.Contains(" "+line+" ", " dd ")
		}
	}
	return false
}
