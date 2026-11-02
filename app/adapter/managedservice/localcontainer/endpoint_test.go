package localcontainer

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestEndpointForwardsBothDirectionsAndClosesOnShutdown(t *testing.T) {
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	ingress, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveEndpoint(ctx, ingress, backend.Addr().String(), 1, time.Second) }()
	client, err := net.DialTimeout("tcp4", ingress.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = backend.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
	server, err := backend.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, direction := range [][2]net.Conn{{server, client}, {client, server}} {
		_ = direction[0].SetDeadline(time.Now().Add(time.Second))
		_ = direction[1].SetDeadline(time.Now().Add(time.Second))
		if _, err := direction[0].Write([]byte("opaque TLS/MySQL bytes")); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, len("opaque TLS/MySQL bytes"))
		if _, err := io.ReadFull(direction[1], buffer); err != nil || string(buffer) != "opaque TLS/MySQL bytes" {
			t.Fatal("stream was not preserved")
		}
	}
	// A slow client cannot reserve unbounded upstream connections.
	excess, err := net.DialTimeout("tcp4", ingress.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer excess.Close()
	_ = excess.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := excess.Read(make([]byte, 1)); err == nil {
		t.Fatal("capacity overflow accepted")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("capacity overflow left open")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("endpoint did not close active streams on shutdown")
	}
}

func TestEndpointClosesIdleStreams(t *testing.T) {
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	ingress, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveEndpoint(ctx, ingress, backend.Addr().String(), 1, 50*time.Millisecond) }()
	client, err := net.DialTimeout("tcp4", ingress.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle connection retained")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("idle connection deadline not enforced")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestEndpointRejectsUnboundedNativeTargetsBeforeListening(t *testing.T) {
	for _, target := range []string{"", "logstash", "http://logstash:8080", "127.0.0.1:8080", "host.docker.internal:8080", "logstash:0", "logstash:65536", "logstash:08080", "logstash:service", "logstash;command:8080"} {
		if err := ServeEndpoint(t.Context(), target); err == nil {
			t.Fatal("accepted an invalid trusted target")
		}
	}
}
