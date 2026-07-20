.PHONY: test fmt vet build schemas verify-network-live

test:
	go test ./...

fmt:
	gofmt -w $$(find cmd internal -name '*.go' -type f)

vet:
	go vet ./...

build:
	mkdir -p dist
	go build -trimpath -o dist/private-vm ./cmd/private-vm
	go build -trimpath -o dist/private-vmd ./cmd/private-vmd
	go build -trimpath -o dist/private-vm-guestd ./cmd/private-vm-guestd

schemas:
	python3 tools/validate_schemas.py
	python3 tools/validate_examples.py

verify-network-live:
	@env \
		PRIVATE_VM_NETWORK_INTEGRATION=1 \
		PRIVATE_VM_NETWORK_IP_BINARY="$$(readlink -f "$$(command -v ip)")" \
		PRIVATE_VM_NETWORK_NFT_BINARY="$$(readlink -f "$$(command -v nft)")" \
		PRIVATE_VM_NETWORK_SYSCTL_BINARY="$$(readlink -f "$$(command -v sysctl)")" \
		PRIVATE_VM_NETWORK_UNSHARE_BINARY="$$(readlink -f "$$(command -v unshare)")" \
		GOMAXPROCS=2 \
		go test -json -p=1 -count=1 -run '^TestLinuxBackendIsolatedIntegration$$' ./internal/network
