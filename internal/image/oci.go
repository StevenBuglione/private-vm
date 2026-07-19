package image

import (
	"context"
	"io"
	"net/http"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

const defaultHTTPRequestTimeout = 5 * time.Minute

// Repository is the read-only OCI surface required by IMG-001. It deliberately
// exposes no push, delete, tag, credential or generic registry operation.
type Repository interface {
	Resolve(context.Context, string) (ocispec.Descriptor, error)
	Fetch(context.Context, ocispec.Descriptor) (io.ReadCloser, error)
}

// RepositoryFactory opens one immutable read-only repository client.
type RepositoryFactory interface {
	Open(repository string) (Repository, error)
}

// ORASFactory creates anonymous HTTPS repositories backed by oras-go. The
// caller may inject a bounded HTTP client for tests. No Docker daemon, local
// credential store or environment credential lookup is used.
type ORASFactory struct {
	HTTPClient *http.Client
}

func (factory ORASFactory) Open(repository string) (Repository, error) {
	repo, err := remote.NewRepository(repository)
	if err != nil {
		return nil, err
	}

	client := factory.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPRequestTimeout}
	} else {
		copy := *client
		if copy.Timeout <= 0 || copy.Timeout > defaultHTTPRequestTimeout {
			copy.Timeout = defaultHTTPRequestTimeout
		}
		client = &copy
	}
	repo.Client = &auth.Client{
		Client: client,
		Cache:  nil,
		// A nil Credential callback is intentionally anonymous.
	}
	repo.MaxMetadataBytes = DefaultLimits().MaxManifestBytes
	return repo, nil
}
