package main

import (
	"context"
	"testing"
)

func TestRunRejectsMissingConfigurationBeforeListening(t *testing.T) {
	if err := run(context.Background(), func(string) string { return "" }); err == nil {
		t.Fatal("missing UI listen address was accepted")
	}
	if err := run(nil, func(string) string { return "127.0.0.1:0" }); err == nil {
		t.Fatal("missing UI process context was accepted")
	}
}
