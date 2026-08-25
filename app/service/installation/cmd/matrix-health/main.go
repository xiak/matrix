package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

const maximumReadinessBytes = 64 * 1024

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], nil); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix process is not ready")
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, supplied *http.Client) error {
	if ctx == nil || len(arguments) != 1 {
		return errors.New("health probe input is invalid")
	}
	target, err := url.Parse(arguments[0])
	if err != nil || !validTarget(target) {
		return errors.New("health probe target is invalid")
	}
	client := supplied
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		client = &http.Client{Transport: transport, Timeout: 2 * time.Second}
	} else {
		clone := *client
		client = &clone
		if client.Timeout <= 0 || client.Timeout > 5*time.Second {
			client.Timeout = 2 * time.Second
		}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return errors.New("health probe request is invalid")
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("health probe is unavailable")
	}
	defer response.Body.Close()
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" ||
		mediaErr != nil || mediaType != "application/json" {
		return errors.New("health probe response is not ready")
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maximumReadinessBytes+1))
	if err != nil || len(content) == 0 || len(content) > maximumReadinessBytes ||
		!json.Valid(content) {
		return errors.New("health probe response is invalid")
	}
	return nil
}

func validTarget(target *url.URL) bool {
	if target == nil || target.Scheme != "http" || target.User != nil ||
		target.Path != "/ready" || target.RawPath != "" || target.RawQuery != "" ||
		target.Fragment != "" {
		return false
	}
	host, port, err := net.SplitHostPort(target.Host)
	if err != nil || host != "127.0.0.1" {
		return false
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	return err == nil && parsedPort != 0
}
