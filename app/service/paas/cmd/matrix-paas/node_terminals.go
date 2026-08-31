package main

import (
	"context"
	"errors"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	nodehttps "github.com/xiak/matrix/app/adapter/node/https"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/port"
	"github.com/xiak/matrix/app/service/paas/internal/apphosting/usecase/executionadmission"
)

type nodeTerminalRouter struct {
	installationID string
	byBinding      map[string]nodeTerminalRoute
}

type nodeTerminalRoute struct {
	targetID paasv1.ResourceID
	client   *nodehttps.Client
}

func terminalRouter(installationID string, bindings []executionadmission.Binding) (*nodeTerminalRouter, error) {
	byBinding := make(map[string]nodeTerminalRoute, len(bindings))
	for _, binding := range bindings {
		client, ok := binding.Adapter.(*nodehttps.Client)
		if !ok || client == nil || paasv1.ValidateID("installationId", installationID) != nil ||
			paasv1.ValidateID("bindingRef", binding.Ref) != nil ||
			paasv1.ValidateID("executionTargetId", string(binding.TargetID)) != nil {
			return nil, errors.New("protected node terminal routes are invalid")
		}
		if _, duplicate := byBinding[binding.Ref]; duplicate {
			return nil, errors.New("protected node terminal routes are duplicated")
		}
		byBinding[binding.Ref] = nodeTerminalRoute{targetID: binding.TargetID, client: client}
	}
	if paasv1.ValidateID("installationId", installationID) != nil {
		return nil, errors.New("protected node terminal routes are invalid")
	}
	return &nodeTerminalRouter{installationID: installationID, byBinding: byBinding}, nil
}

func (router *nodeTerminalRouter) OpenTerminal(
	ctx context.Context,
	bindingRef string,
	request nodev1.TerminalOpenRequest,
) (port.TerminalConnection, error) {
	if router == nil || ctx == nil || request.BindingRef != bindingRef ||
		paasv1.ValidateID("bindingRef", bindingRef) != nil {
		return nil, port.ErrTerminalRejected
	}
	route, found := router.byBinding[bindingRef]
	if !found || request.Identity != (nodev1.Identity{}) ||
		request.Request.ExecutionTargetID != route.targetID {
		return nil, port.ErrTerminalRejected
	}
	request.Identity = nodev1.Identity{
		InstallationID: router.installationID, ExecutionTargetID: route.targetID,
	}
	connection, err := route.client.OpenTerminal(ctx, request)
	if err != nil {
		switch {
		case errors.Is(err, nodehttps.ErrTerminalUnsupported):
			return nil, port.ErrTerminalUnsupported
		case errors.Is(err, nodehttps.ErrTerminalUnavailable):
			return nil, port.ErrTerminalUnavailable
		default:
			return nil, port.ErrTerminalRejected
		}
	}
	return connection, nil
}
