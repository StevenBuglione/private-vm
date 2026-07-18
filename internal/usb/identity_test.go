package usb

import "testing"

func TestRejectsCompositeDevice(t *testing.T) {
	id := Identity{
		VendorID: "1234", ProductID: "5678", Serial: "x",
		PortPath: "1-2", Capacity: 1024,
		Interfaces: []string{"08:06:50", "03:01:01"},
	}
	if err := id.ValidateForEnrollment(); err == nil {
		t.Fatal("expected composite interface rejection")
	}
}
