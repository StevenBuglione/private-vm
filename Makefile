.PHONY: test fmt vet build schemas

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
