//go:build !linux

package runnersandboxdocker

import "net/http"

func newEngineHTTPClient(string) (*http.Client, error) {
	return nil, ErrUnsupported
}

func freeStorageBytes(string) (uint64, error) {
	return 0, ErrUnsupported
}
