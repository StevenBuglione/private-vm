package guestvpn

import (
	"context"
	"errors"
	"testing"

	"github.com/StevenBuglione/private-vm/internal/session"
)

type orderedOnlineService struct {
	started bool
	starts  int
	stops   int
	fail    bool
}

func (service *orderedOnlineService) Start(context.Context) error {
	service.starts++
	service.started = true
	if service.fail {
		return errors.New("fixture start failure")
	}
	return nil
}

func (service *orderedOnlineService) Stop(context.Context) error {
	service.stops++
	service.started = false
	return nil
}

type onlineAwareVerifier struct{ service *orderedOnlineService }

func (verifier onlineAwareVerifier) Verify(context.Context, RolePolicy) (Proof, error) {
	if verifier.service == nil || !verifier.service.started {
		return Proof{}, errors.New("local service started out of order")
	}
	return Proof{
		Handshake: true, DNSThroughTunnel: true, DNSBypassBlocked: true,
		IPv4ThroughTunnel: true, IPv4BypassBlocked: true, IPv6BypassBlocked: true, TorrentBound: true,
	}, nil
}

func TestControllerStartsAndStopsDownloaderServiceInsideVPNLifecycle(t *testing.T) {
	service := &orderedOnlineService{}
	controller, err := NewControllerWithOnlineService(
		&fakeBackend{}, onlineAwareVerifier{service: service}, service,
		RolePolicy{Role: session.RoleDownloader, RequireTorrentBinding: true}, validUnderlay(),
	)
	if err != nil {
		t.Fatal(err)
	}
	status, err := controller.Configure(t.Context(), testProfile(t, false))
	if err != nil || status.State != StateVerified || service.starts != 1 || service.stops != 0 {
		t.Fatalf("configure status=%+v err=%v service=%+v", status, err, service)
	}
	if err := controller.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if service.started || service.stops != 1 {
		t.Fatalf("stop service=%+v", service)
	}
}

func TestControllerCleansPartialDownloaderServiceStart(t *testing.T) {
	service := &orderedOnlineService{fail: true}
	controller, err := NewControllerWithOnlineService(
		&fakeBackend{}, onlineAwareVerifier{service: service}, service,
		RolePolicy{Role: session.RoleDownloader, RequireTorrentBinding: true}, validUnderlay(),
	)
	if err != nil {
		t.Fatal(err)
	}
	status, err := controller.Configure(t.Context(), testProfile(t, false))
	if err == nil || status.State != StateDegraded || service.started || service.starts != 1 || service.stops != 1 {
		t.Fatalf("partial start status=%+v err=%v service=%+v", status, err, service)
	}
}
