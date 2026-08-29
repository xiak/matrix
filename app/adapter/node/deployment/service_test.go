package deployment

import (
	"context"
	"errors"
	"strings"
	"testing"

	composeadapter "github.com/xiak/matrix/app/adapter/apphosting/compose"
)

type runtimeStub struct{}

func (runtimeStub) Apply(context.Context, composeadapter.RuntimeProject) error { return nil }
func (runtimeStub) Stop(context.Context, composeadapter.RuntimeProject) error  { return nil }
func (runtimeStub) Observe(context.Context, composeadapter.RuntimeProject) ([]composeadapter.RuntimeContainer, error) {
	return nil, nil
}

func TestNodeDeploymentServiceRequiresAndSanitizesRuntimeReadiness(t *testing.T) {
	if _, err := New(Config{
		BindingRef: "binding-a", BindingRoot: t.TempDir(), Runtime: runtimeStub{},
	}); err == nil {
		t.Fatal("node Deployment service accepted a runtime without readiness")
	}
	native := errors.New("docker socket /private/path password=secret is unavailable")
	service, err := New(Config{
		BindingRef: "binding-a", BindingRoot: t.TempDir(), Runtime: runtimeStub{},
		Readiness: func(context.Context) error { return native },
	})
	if err != nil {
		t.Fatal(err)
	}
	err = service.Ready(context.Background())
	if err == nil || errors.Is(err, native) || strings.Contains(err.Error(), "/private/path") ||
		strings.Contains(err.Error(), "password") {
		t.Fatalf("native readiness detail escaped: %v", err)
	}
}
