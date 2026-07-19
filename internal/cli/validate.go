package cli

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
)

var (
	sessionIDPattern   = regexp.MustCompile(`^pvm-[0-9a-f]{32}$`)
	opaqueIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$`)
	sizePattern        = regexp.MustCompile(`^([0-9]+)(B|KiB|MiB|GiB|TiB)$`)
	usbDeviceIDPattern = regexp.MustCompile(`^usbdev-[0-9a-f]{16}$`)
	usbLabelPattern    = regexp.MustCompile(`^[A-Z0-9][A-Z0-9_-]{0,31}$`)
)

const maximumFileSelectionBytes = 4096*10 + 4095

func usageError(message, remediation string) *apperror.Error {
	return apperror.New("CLI_USAGE", exitcode.Usage, message, remediation)
}

func validateUSBDeviceID(value string) error {
	if !usbDeviceIDPattern.MatchString(value) {
		return usageError("The USB discovery identifier is invalid.", "Run private-vm usb list again and use its exact usbdev identifier.")
	}
	return nil
}

func validateUSBLabel(value string) error {
	if !usbLabelPattern.MatchString(value) {
		return usageError("The USB enrollment label is invalid.", "Use 1-32 uppercase letters, digits, underscores, or hyphens.")
	}
	return nil
}

func validateGlobalOptions(options Options) error {
	if options.Timeout <= 0 || options.Timeout > maximumTimeout {
		return usageError(
			"The operation timeout must be greater than zero and at most 24 hours.",
			"Set --timeout to a positive Go duration such as 5m or 1h.",
		)
	}
	if !oneOf(options.LogLevel, "error", "warn", "info", "debug") {
		return usageError(
			"The log level is not supported.",
			"Set --log-level to error, warn, info, or debug.",
		)
	}
	if options.ConfigPath != "" {
		if err := validatePath(options.ConfigPath); err != nil {
			return err
		}
	}
	return nil
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func enum(value, label string, allowed ...string) error {
	if oneOf(value, allowed...) {
		return nil
	}
	return usageError(
		"The selected "+label+" is not supported.",
		"Choose one of the documented "+label+" values.",
	)
}

func optionalEnum(value, label string, allowed ...string) error {
	if value == "" {
		return nil
	}
	return enum(value, label, allowed...)
}

func validateSessionID(value string, required bool) error {
	if value == "" && !required {
		return nil
	}
	if !sessionIDPattern.MatchString(value) {
		return usageError(
			"The session identifier is invalid.",
			"Use the exact pvm session identifier reported by private-vm session list.",
		)
	}
	return nil
}

func validateOpaqueID(value, label string, required bool) error {
	if value == "" && !required {
		return nil
	}
	if !opaqueIDPattern.MatchString(value) {
		return usageError(
			"The "+label+" identifier is invalid.",
			"Use the exact identifier reported by the corresponding private-vm list command.",
		)
	}
	return nil
}

func validatePath(value string) error {
	if value == "" || len(value) > 4096 || !utf8.ValidString(value) || hasControl(value) {
		return usageError(
			"A supplied path is invalid.",
			"Provide one non-empty UTF-8 path no longer than 4096 bytes.",
		)
	}
	return nil
}

func validateOCIReference(value string) error {
	if value == "" || len(value) > 512 || !utf8.ValidString(value) || hasControl(value) || strings.ContainsAny(value, " \t\r\n") {
		return usageError(
			"The image reference is invalid.",
			"Provide a non-empty OCI reference no longer than 512 bytes without whitespace.",
		)
	}
	return nil
}

func hasControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func parseIECSize(value string) (uint64, error) {
	matches := sizePattern.FindStringSubmatch(value)
	if matches == nil {
		return 0, usageError(
			"The memory size is invalid.",
			"Use an integer followed by B, KiB, MiB, GiB, or TiB.",
		)
	}
	amount, err := strconv.ParseUint(matches[1], 10, 64)
	if err != nil {
		return 0, usageError(
			"The memory size is too large.",
			"Choose a memory size between 2 GiB and 256 GiB.",
		)
	}
	multiplier := uint64(1)
	switch matches[2] {
	case "KiB":
		multiplier = 1 << 10
	case "MiB":
		multiplier = 1 << 20
	case "GiB":
		multiplier = 1 << 30
	case "TiB":
		multiplier = 1 << 40
	}
	if amount > math.MaxUint64/multiplier {
		return 0, usageError(
			"The memory size is too large.",
			"Choose a memory size between 2 GiB and 256 GiB.",
		)
	}
	return amount * multiplier, nil
}

func validateDesktopResources(memory string, cpus int, cpusSet bool) error {
	if memory != "" {
		bytes, err := parseIECSize(memory)
		if err != nil {
			return err
		}
		if bytes < 2<<30 || bytes > 256<<30 {
			return usageError(
				"Desktop memory must be between 2 GiB and 256 GiB.",
				"Choose a bounded memory allocation suitable for the host.",
			)
		}
	}
	if cpusSet && (cpus < 1 || cpus > 64) {
		return usageError(
			"The CPU count must be between 1 and 64 when specified.",
			"Set --cpus to an integer from 1 through 64.",
		)
	}
	return nil
}

func validateFileSelection(value string) error {
	_, err := parseFileSelection(value)
	return err
}

func parseFileSelection(value string) ([]uint32, error) {
	if value == "" {
		return nil, usageError(
			"At least one torrent file index is required.",
			"Set --files to a comma-separated list of positive indexes.",
		)
	}
	if len(value) > maximumFileSelectionBytes {
		return nil, usageError(
			"The torrent file selection is too large.",
			"Select at most 4096 unique positive 32-bit file indexes.",
		)
	}
	parts := strings.Split(value, ",")
	if len(parts) > 4096 {
		return nil, usageError(
			"Too many torrent file indexes were selected.",
			"Select at most 4096 unique file indexes.",
		)
	}
	seen := make(map[uint64]struct{}, len(parts))
	indexes := make([]uint32, 0, len(parts))
	for _, part := range parts {
		if part == "" || strings.TrimSpace(part) != part {
			return nil, invalidFileSelection()
		}
		index, err := strconv.ParseUint(part, 10, 32)
		if err != nil || index == 0 {
			return nil, invalidFileSelection()
		}
		if _, duplicate := seen[index]; duplicate {
			return nil, invalidFileSelection()
		}
		seen[index] = struct{}{}
		indexes = append(indexes, uint32(index))
	}
	return indexes, nil
}

func invalidFileSelection() error {
	return usageError(
		"The torrent file selection is invalid.",
		"Use unique positive decimal indexes separated only by commas.",
	)
}

func exactArgs(count int) cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		if len(args) != count {
			return usageError(
				"The command received the wrong number of positional arguments.",
				"Run private-vm --help and provide exactly the documented arguments.",
			)
		}
		return nil
	}
}

func noArgs(command *cobra.Command, args []string) error {
	return exactArgs(0)(command, args)
}

func requireSubcommand(_ *cobra.Command, _ []string) error {
	return usageError(
		"A subcommand is required.",
		"Run the command with --help and select one documented subcommand.",
	)
}

func validateExclusive(selected int, required bool, message, remediation string) error {
	if selected > 1 || (required && selected != 1) {
		return usageError(message, remediation)
	}
	return nil
}
