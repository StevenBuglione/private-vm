package cli

import (
	"context"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/systeminstall"
)

type recordingFallbackInvoker struct {
	called bool
	id     CommandID
	intent Intent
}

func (invoker *recordingFallbackInvoker) Invoke(_ context.Context, id CommandID, intent Intent) (Result, error) {
	invoker.called = true
	invoker.id = id
	invoker.intent = intent
	return Result{Code: CodeSessionStatus, Data: SessionPayload{}}, nil
}

func TestSystemInstallInvokerDelegatesDaemonCommands(t *testing.T) {
	fallback := &recordingFallbackInvoker{}
	invoker := NewSystemInstallInvokerWithFallback(systeminstall.Installer{}, fallback)
	intent := SessionIntent{SessionID: "pvm-0123456789abcdef0123456789abcdef"}

	result, err := invoker.Invoke(t.Context(), "session.status", intent)
	if err != nil {
		t.Fatal(err)
	}
	if !fallback.called || fallback.id != "session.status" || fallback.intent != intent {
		t.Fatalf("fallback call = called:%v id:%q intent:%#v", fallback.called, fallback.id, fallback.intent)
	}
	if result.Code != CodeSessionStatus {
		t.Fatalf("result code = %q", result.Code)
	}
}
