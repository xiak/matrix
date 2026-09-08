//go:build linux

package runnersandboxdocker

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func newEngineHTTPClient(socketPath string) (*http.Client, error) {
	info, err := os.Lstat(socketPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o007 != 0 {
		return nil, errors.Join(ErrUnavailable, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return nil, ErrUnavailable
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		ForceAttemptHTTP2:      false,
		DisableCompression:     true,
		MaxIdleConns:           4,
		MaxIdleConnsPerHost:    4,
		MaxConnsPerHost:        4,
		IdleConnTimeout:        30 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		ExpectContinueTimeout:  1 * time.Second,
		MaxResponseHeaderBytes: 64 * 1024,
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return ErrUnavailable
		},
	}, nil
}

func freeStorageBytes(rootPath string) (uint64, error) {
	info, err := os.Lstat(rootPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		info.Mode().Perm() != 0o700 {
		return 0, errors.Join(ErrUnavailable, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return 0, ErrUnavailable
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(rootPath, &filesystem); err != nil {
		return 0, errors.Join(ErrUnavailable, err)
	}
	if filesystem.Bsize <= 0 || filesystem.Bavail > ^uint64(0)/uint64(filesystem.Bsize) {
		return 0, ErrUnavailable
	}
	return filesystem.Bavail * uint64(filesystem.Bsize), nil
}
