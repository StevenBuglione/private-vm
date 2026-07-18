package preflight

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
)

type Doctor struct {
	Strict bool
}

func (d Doctor) Run() Report {
	var out []Diagnostic
	blocking := false

	add := func(diag Diagnostic) {
		out = append(out, diag)
		if diag.Severity == SeverityBlocking {
			blocking = true
		}
	}

	if runtime.GOOS != "linux" {
		add(Diagnostic{
			Code: "HOST_OS_UNSUPPORTED", Severity: SeverityBlocking,
			Summary:     "private-vm requires Linux.",
			Remediation: "Run on a supported NixOS, Fedora, Ubuntu, or Debian host.",
		})
	} else {
		add(Diagnostic{Code: "HOST_OS_LINUX", Severity: SeverityInfo, Summary: "Linux host detected."})
	}

	if _, err := os.Stat("/dev/kvm"); err != nil {
		add(Diagnostic{
			Code: "KVM_UNAVAILABLE", Severity: SeverityBlocking,
			Summary:     "The KVM device is unavailable.",
			Remediation: "Enable virtualization in firmware, load KVM modules, and grant access to /dev/kvm.",
		})
	} else {
		f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
		if err != nil {
			add(Diagnostic{
				Code: "KVM_PERMISSION_DENIED", Severity: SeverityBlocking,
				Summary:     "The current user cannot open /dev/kvm.",
				Remediation: "Install the host module/package and confirm KVM group membership.",
			})
		} else {
			_ = f.Close()
			add(Diagnostic{Code: "KVM_USABLE", Severity: SeverityInfo, Summary: "KVM is usable."})
		}
	}

	for _, name := range []string{"qemu-system-x86_64", "cryptsetup", "nft", "ip"} {
		if _, err := exec.LookPath(name); err != nil {
			add(Diagnostic{
				Code:        "COMMAND_MISSING_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")),
				Severity:    SeverityBlocking,
				Summary:     fmt.Sprintf("Required command %q was not found.", name),
				Remediation: "Install the full private-vm host package or NixOS module.",
			})
		}
	}

	if stat, err := os.Stat("/run"); err == nil {
		if s, ok := stat.Sys().(*syscall.Stat_t); ok && s.Mode != 0 {
			add(Diagnostic{Code: "RUNTIME_DIRECTORY_PRESENT", Severity: SeverityInfo, Summary: "/run is available."})
		}
	}

	if _, err := os.Stat("/sys/power/disk"); err == nil {
		sev := SeverityWarning
		if d.Strict {
			sev = SeverityBlocking
		}
		add(Diagnostic{
			Code: "HIBERNATION_REVIEW_REQUIRED", Severity: sev,
			Summary:     "The host exposes hibernation support; private-vm cannot prove it is disabled.",
			Remediation: "Disable hibernation and resume support for strict operation.",
			Overridable: !d.Strict,
		})
	}

	return Report{Runnable: !blocking, Diagnostics: out}
}
