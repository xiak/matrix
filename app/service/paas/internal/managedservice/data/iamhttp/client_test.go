package iamhttp

import (
	"testing"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/port"
)

func TestIAMRequestUsesOnlyTheExplicitResourceShape(t *testing.T) {
	tests := []struct {
		name    string
		request port.AuthorizationRequest
		mode    iamv1.AuthorizationResourceMode
		usage   iamv1.AuthorizationCollectionUsage
	}{
		{
			name: "collection list",
			request: port.AuthorizationRequest{
				Action: port.AuthorizeInstallationRead,
				Resource: port.ResourceReference{
					Kind: port.ResourceServiceInstallation,
					ID:   "collection",
				},
				ResourceMode:    iamv1.AuthorizationResourceCollection,
				CollectionUsage: iamv1.AuthorizationCollectionList,
				RequestID:       "request-installation-list",
			},
			mode: iamv1.AuthorizationResourceCollection, usage: iamv1.AuthorizationCollectionList,
		},
		{
			name: "instance named collection",
			request: port.AuthorizationRequest{
				Action: port.AuthorizeInstallationRead,
				Resource: port.ResourceReference{
					Kind: port.ResourceServiceInstallation,
					ID:   "collection",
				},
				ResourceMode: iamv1.AuthorizationResourceInstance,
				RequestID:    "request-installation-instance",
			},
			mode: iamv1.AuthorizationResourceInstance,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := toIAMRequest(test.request)
			if err != nil {
				t.Fatalf("map managed-service request: %v", err)
			}
			if request.Resource.ID != "collection" || request.ResourceMode != test.mode ||
				request.CollectionUsage != test.usage {
				t.Fatalf("IAM request shape=%#v", request)
			}
		})
	}
}
