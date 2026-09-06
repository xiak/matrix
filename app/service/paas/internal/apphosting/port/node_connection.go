package port

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

// EnrolledNodeConnection is the protected, long-lived route committed with a
// self-enrolled ExecutionTarget. It contains no certificate or private key;
// those remain installation-owned process input.
type EnrolledNodeConnection struct {
	InstallationID      string
	ExecutionTargetID   paasv1.ResourceID
	ControllerID        string
	BindingRef          string
	Endpoint            string
	IdentityFingerprint string
	Enabled             bool
}

func ValidateEnrolledNodeConnection(value EnrolledNodeConnection) error {
	if paasv1.ValidateID("installationId", value.InstallationID) != nil ||
		paasv1.ValidateID("executionTargetId", string(value.ExecutionTargetID)) != nil ||
		paasv1.ValidateID("controllerId", value.ControllerID) != nil ||
		paasv1.ValidateID("bindingRef", value.BindingRef) != nil ||
		paasv1.ValidateDigest("identityFingerprint", value.IdentityFingerprint) != nil ||
		!strings.HasPrefix(value.BindingRef, "node-binding-") || len(value.BindingRef) != len("node-binding-")+32 ||
		!lowerHex(value.BindingRef[len("node-binding-"):]) ||
		!privateNodeEndpoint(value.Endpoint) {
		return errors.New("enrolled node connection is invalid")
	}
	return nil
}

func lowerHex(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func privateNodeEndpoint(text string) bool {
	value, err := url.Parse(text)
	if err != nil || value.Scheme != "https" || value.User != nil || value.Path != "" ||
		value.RawPath != "" || value.RawQuery != "" || value.Fragment != "" || value.Host == "" {
		return false
	}
	host, portText, err := net.SplitHostPort(value.Host)
	if err != nil {
		return false
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Is4In6() || (!address.IsPrivate() && !address.IsLoopback()) {
		return false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	return err == nil && port >= 1024 && host == address.String() &&
		portText == strconv.FormatUint(port, 10)
}

type EnrolledNodeConnectionReader interface {
	LoadEnrolledNodeConnection(
		context.Context,
		string,
		paasv1.ResourceID,
	) (EnrolledNodeConnection, bool, error)
}
