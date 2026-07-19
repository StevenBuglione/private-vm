package usb

import (
	"context"
	"testing"
)

func TestApprovedSourceRegistryAcceptsTypedScannerAndWorkstationSourcesOnce(t *testing.T) {
	registry := NewApprovedSourceRegistry()
	for _, role := range []SourceRole{SourceScanner, SourceWorkstation} {
		selection := SourceSelection{
			Role:      role,
			SessionID: "pvm-0123456789abcdef0123456789abcdef",
			OutputID:  "output-opaque-01",
		}
		source := &fakeApprovedSource{}
		if err := registry.Register(selection, func(context.Context) (ApprovedSource, error) { return source, nil }); err != nil {
			t.Fatalf("register %s: %v", role, err)
		}
		opened, err := registry.OpenApproved(t.Context(), selection)
		if err != nil || opened != source {
			t.Fatalf("open %s: source=%p err=%v", role, opened, err)
		}
		if _, err := registry.OpenApproved(t.Context(), selection); err == nil {
			t.Fatalf("%s source reopened after one-use handoff", role)
		}
	}
}

func TestApprovedSourceRegistryRejectsPathLikeOutputSelection(t *testing.T) {
	selection := SourceSelection{
		Role:      SourceScanner,
		SessionID: "pvm-0123456789abcdef0123456789abcdef",
		OutputID:  "../../host/path",
	}
	if err := NewApprovedSourceRegistry().Register(selection, func(context.Context) (ApprovedSource, error) { return &fakeApprovedSource{}, nil }); err == nil {
		t.Fatal("path-like approved source selection unexpectedly registered")
	}
}

func TestApprovedOutputRequiresWorkstationExportState(t *testing.T) {
	output := ApprovedOutput{
		SourceRole:  SourceWorkstation,
		OutputID:    "output-opaque-01",
		LogicalName: "export.txt",
		MediaType:   "text/plain",
		Size:        1,
		SourceDigest: func() Digest {
			var value [32]byte
			value[0] = 1
			return NewDigest(value)
		}(),
	}
	if err := output.Validate(1024); err == nil {
		t.Fatal("unauthenticated workstation Export state unexpectedly passed")
	}
	output.ExportStateAuthenticated = true
	output.ExportStateReady = true
	if err := output.Validate(1024); err != nil {
		t.Fatalf("authenticated workstation Export state rejected: %v", err)
	}
}
