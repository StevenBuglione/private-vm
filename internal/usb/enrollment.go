package usb

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	EnrollmentSchemaVersion = 1
	DefaultFilesystem       = "luks2-ext4"
	MaximumEnrollmentBytes  = 32 << 10
)

var (
	enrollmentIDPattern = regexp.MustCompile(`^usb-[0-9a-f]{16}$`)
	labelPattern        = regexp.MustCompile(`^[A-Z0-9][A-Z0-9_-]{0,31}$`)
)

type Enrollment struct {
	SchemaVersion int      `json:"schema_version"`
	EnrollmentID  string   `json:"enrollment_id"`
	Label         string   `json:"label"`
	Identity      Identity `json:"identity"`
	Filesystem    string   `json:"filesystem"`
}

func NewEnrollment(identity Identity, label string) (Enrollment, error) {
	identity = identity.normalized()
	if err := identity.ValidateForEnrollment(); err != nil {
		return Enrollment{}, err
	}
	sum, err := identity.fingerprint()
	if err != nil {
		return Enrollment{}, err
	}
	enrollment := Enrollment{
		SchemaVersion: EnrollmentSchemaVersion,
		EnrollmentID:  fmt.Sprintf("usb-%x", sum[:8]),
		Label:         strings.TrimSpace(label),
		Identity:      identity,
		Filesystem:    DefaultFilesystem,
	}
	if err := enrollment.Validate(); err != nil {
		return Enrollment{}, err
	}
	return enrollment, nil
}

func (e Enrollment) Validate() error {
	if e.SchemaVersion != EnrollmentSchemaVersion {
		return errors.New("unsupported USB enrollment schema version")
	}
	if !enrollmentIDPattern.MatchString(e.EnrollmentID) {
		return errors.New("USB enrollment ID is invalid")
	}
	if !labelPattern.MatchString(e.Label) {
		return errors.New("USB enrollment label is invalid")
	}
	if e.Filesystem != DefaultFilesystem {
		return errors.New("USB enrollment filesystem is unsupported")
	}
	if err := e.Identity.ValidateForEnrollment(); err != nil {
		return err
	}
	sum, err := e.Identity.fingerprint()
	if err != nil {
		return err
	}
	if e.EnrollmentID != fmt.Sprintf("usb-%x", sum[:8]) {
		return errors.New("USB enrollment ID does not match its identity")
	}
	return nil
}

func EncodeEnrollment(enrollment Enrollment) ([]byte, error) {
	if err := enrollment.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(enrollment, "", "  ")
	if err != nil {
		return nil, errors.New("encode USB enrollment")
	}
	data = append(data, '\n')
	if len(data) > MaximumEnrollmentBytes {
		return nil, errors.New("USB enrollment exceeds its size limit")
	}
	return data, nil
}

func DecodeEnrollment(reader io.Reader) (Enrollment, error) {
	if reader == nil {
		return Enrollment{}, errors.New("USB enrollment reader is required")
	}
	limited := io.LimitReader(reader, MaximumEnrollmentBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return Enrollment{}, errors.New("read USB enrollment")
	}
	if len(data) > MaximumEnrollmentBytes {
		return Enrollment{}, errors.New("USB enrollment exceeds its size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var enrollment Enrollment
	if err := decoder.Decode(&enrollment); err != nil {
		return Enrollment{}, errors.New("USB enrollment is malformed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Enrollment{}, errors.New("USB enrollment has trailing data")
	}
	if err := enrollment.Validate(); err != nil {
		return Enrollment{}, err
	}
	return enrollment, nil
}

func USBGuardRule(enrollment Enrollment) (string, error) {
	if err := enrollment.Validate(); err != nil {
		return "", err
	}
	identity := enrollment.Identity.normalized()
	serial := ""
	if identity.Serial != "" {
		serial = ` serial "` + identity.Serial + `"`
	}
	interfaces := make([]string, len(identity.Interfaces))
	copy(interfaces, identity.Interfaces)
	return fmt.Sprintf(
		`allow id %s:%s%s hash "%s" via-port "%s" with-interface equals { %s }`,
		identity.VendorID,
		identity.ProductID,
		serial,
		identity.USBGuardHash,
		identity.PortPath,
		strings.Join(interfaces, " "),
	), nil
}
