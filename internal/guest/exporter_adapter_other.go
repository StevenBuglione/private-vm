//go:build !linux

package guest

import "errors"

func NewFixedExporterAdapter() (ExporterAdapter, error) {
	return nil, errors.New("fixed exporter adapter is supported only on Linux")
}
