package identityaccess

import (
	"cmp"
	"context"
	"slices"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

// ListServiceRoleTemplates returns release-owned template metadata only after
// the current user is authorized in their authenticated account. An ACTIVE
// template is not account consent and this projection contains no service
// credential or account-selected authority.
func (service *Authority) ListServiceRoleTemplates(ctx context.Context, credential iamv1.Secret, requestID string) (iamv1.ServiceRoleTemplateList, error) {
	if iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.ServiceRoleTemplateList{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMServiceRoleTemplateList,
		iamv1.AuthorizationResourceInstance, "", iamv1.ResourceReference{Kind: iamv1.ResourceAccount}, requestID,
		func(_ context.Context, _ Transaction, _ SessionCredential, _ iamv1.AuthorizationDecision, _ time.Time) (iamv1.ServiceRoleTemplateList, error) {
			templates, err := authority.ServiceRoleTemplates()
			if err != nil {
				return iamv1.ServiceRoleTemplateList{}, ErrUnavailable
			}
			slices.SortFunc(templates, func(left, right iamv1.ServiceRoleTemplate) int {
				return cmp.Compare(left.ID, right.ID)
			})
			result := iamv1.ServiceRoleTemplateList{
				APIVersion: iamv1.APIVersion,
				Kind:       "ServiceRoleTemplateList",
				Items:      templates,
			}
			if iamv1.ValidateServiceRoleTemplateList(result) != nil {
				return iamv1.ServiceRoleTemplateList{}, ErrUnavailable
			}
			return result, nil
		})
}
