package orchestrator

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/network"
)

const policyAuditSessionID = "pvm-77777777777777777777777777777777"

type fakeNetworkPolicyAuditHandle struct {
	proof network.PolicyAudit
	err   error
}

func (handle *fakeNetworkPolicyAuditHandle) AuditPolicy(context.Context) (network.PolicyAudit, error) {
	return handle.proof, handle.err
}

func TestNetworkPolicyAuditorReturnsBooleanOnlyLiveProof(t *testing.T) {
	handle := &fakeNetworkPolicyAuditHandle{proof: network.PolicyAudit{
		NamespacePolicyPresent: true,
		HostPolicyPresent:      true,
		ForbiddenEgressZero:    true,
	}}
	auditor := networkPolicyAuditor{sessionID: policyAuditSessionID, handle: handle}
	proof, err := auditor.Verify(context.Background(), policyAuditSessionID)
	if err != nil || !proof.complete() {
		t.Fatalf("policy proof = %#v, %v", proof, err)
	}
	handle.proof.ForbiddenEgressZero = false
	proof, err = auditor.Verify(context.Background(), policyAuditSessionID)
	if err != nil || proof.complete() || proof.ForbiddenEgressZero {
		t.Fatalf("nonzero counter proof passed = %#v, %v", proof, err)
	}
}

func TestNetworkPolicyAuditorRejectsMismatchFailureCancellationAndTimeout(t *testing.T) {
	const sensitive = "198.51.100.77:51820"
	handle := &fakeNetworkPolicyAuditHandle{err: errors.New("synthetic nft output " + sensitive)}
	auditor := networkPolicyAuditor{sessionID: policyAuditSessionID, handle: handle}
	if _, err := auditor.Verify(context.Background(), "pvm-66666666666666666666666666666666"); !errors.Is(err, ErrNetworkedNotVerified) {
		t.Fatalf("mismatched session audit = %v", err)
	}
	if _, err := auditor.Verify(context.Background(), policyAuditSessionID); !errors.Is(err, ErrNetworkedNotVerified) || strings.Contains(err.Error(), sensitive) {
		t.Fatalf("unredacted policy failure = %v", err)
	}
	for _, expected := range []error{context.Canceled, context.DeadlineExceeded} {
		handle.err = expected
		if _, err := auditor.Verify(context.Background(), policyAuditSessionID); !errors.Is(err, expected) {
			t.Fatalf("context result %v mapped to %v", expected, err)
		}
	}
}
