package authority

import (
	"cmp"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"slices"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

var (
	ErrInvalidCursorKey = errors.New("IAM cursor key is invalid")
	ErrInvalidCursor    = errors.New("IAM cursor is invalid")
)

const cursorLifetime = 15 * time.Minute
const cursorHeaderBytes = 8 + 8 + sha256.Size + 1

// CursorCodec protects continuation, not permissions. Each use case still
// authenticates and authorizes every page in its current transaction snapshot.
// A zero value is deliberately unusable; no process-local random fallback exists.
type CursorCodec struct {
	key   [sha256.Size]byte
	ready bool
}

// DirectoryQuery has only the currently supported closed directory routes.
// Their order and page size are fixed and included in the binding, not caller
// options that can silently drift between requests.
type DirectoryQuery struct {
	// InstallationID is the sealed deployment owning this key. It is not the
	// subject's platform permission context and never grants platform authority.
	InstallationID string
	Action         iamv1.Action
	Resource       iamv1.ResourceReference
	// Self discovery is not a management action. These private revisions come
	// from the authenticated database snapshot, never from caller selectors.
	AssumableRoles *RoleDiscoveryRevision         `json:",omitempty"`
	RoleSessions   *RoleSessionDirectoryQuery     `json:",omitempty"`
	LoginSessions  *LoginSessionDirectoryRevision `json:",omitempty"`
}

type LoginSessionDirectoryRevision struct {
	CredentialGeneration uint64 `json:"credentialGeneration"`
}

// Private snapshot and closed filters protect continuation; they grant no
// permission and are never returned as a northbound selector or permit.
type RoleSessionDirectoryRevision struct {
	CredentialGeneration        uint64                      `json:"credentialGeneration"`
	DirectoryRevision           uint64                      `json:"directoryRevision"`
	UserAuthorizationGeneration uint64                      `json:"userAuthorizationGeneration"`
	Groups                      []RoleSourceGroupGeneration `json:"groups"`
}

type RoleSessionDirectoryQuery struct {
	Revision RoleSessionDirectoryRevision
	Filter   iamv1.RoleSessionFilter
}

func ValidateRoleSessionDirectoryRevision(value RoleSessionDirectoryRevision) error {
	if value.CredentialGeneration == 0 || value.CredentialGeneration > 9007199254740991 ||
		value.DirectoryRevision == 0 || value.DirectoryRevision > 9007199254740991 {
		return ErrAuthorityUnavailable
	}
	return ValidateRoleSourceAuthority(2, value.UserAuthorizationGeneration, value.Groups)
}

type RoleDiscoveryRevision struct {
	CredentialGeneration uint64 `json:"credentialGeneration"`
	DirectoryRevision    uint64 `json:"directoryRevision"`
}

func NewCursorCodec(key []byte) (CursorCodec, error) {
	if len(key) != sha256.Size {
		return CursorCodec{}, ErrInvalidCursorKey
	}
	codec := CursorCodec{ready: true}
	copy(codec.key[:], key)
	return codec, nil
}

func (codec CursorCodec) Encode(subject SubjectContext, query DirectoryQuery, after string, now time.Time) (string, error) {
	if !codec.ready {
		return "", ErrInvalidCursorKey
	}
	if iamv1.ValidateID("after", after) != nil {
		return "", ErrInvalidCursor
	}
	binding, err := codec.binding(subject, query, now)
	if err != nil {
		return "", err
	}
	expires := now.Add(cursorLifetime)
	if subject.Session.ExpiresAt.Before(expires) {
		expires = subject.Session.ExpiresAt
	}
	position := []byte(after)
	prefix := "ic1."
	if query.AssumableRoles != nil {
		prefix = "ir1."
		protector, err := codec.positionCipher(binding)
		if err != nil {
			return "", ErrInvalidCursor
		}
		position = protector.Seal(nil, nil, position, roleDiscoveryCursorAAD(binding))
	}
	defer clear(position)
	payload := make([]byte, cursorHeaderBytes+len(position))
	binary.BigEndian.PutUint64(payload[:8], uint64(now.UnixMicro()))
	binary.BigEndian.PutUint64(payload[8:16], uint64(expires.UnixMicro()))
	copy(payload[16:48], binding)
	payload[48] = byte(len(position))
	copy(payload[cursorHeaderBytes:], position)
	envelope := append(payload, codec.tag(payload)...)
	result := prefix + base64.RawURLEncoding.EncodeToString(envelope)
	clear(envelope)
	return result, nil
}

func (codec CursorCodec) Decode(value string, subject SubjectContext, query DirectoryQuery, now time.Time) (string, error) {
	if !codec.ready {
		return "", ErrInvalidCursorKey
	}
	validate := iamv1.ValidatePageCursor
	if query.AssumableRoles != nil {
		validate = iamv1.ValidateRoleDiscoveryCursor
	}
	if validate(value) != nil {
		return "", ErrInvalidCursor
	}
	envelope, err := base64.RawURLEncoding.Strict().DecodeString(value[4:])
	maximumPosition := 128
	if query.AssumableRoles != nil {
		maximumPosition += 28 // AES-GCM's random nonce and authentication tag.
	}
	if err != nil || len(envelope) <= cursorHeaderBytes+sha256.Size || len(envelope) > cursorHeaderBytes+maximumPosition+sha256.Size {
		clear(envelope)
		return "", ErrInvalidCursor
	}
	defer clear(envelope)
	payload, tag := envelope[:len(envelope)-sha256.Size], envelope[len(envelope)-sha256.Size:]
	if !hmac.Equal(tag, codec.tag(payload)) || int(payload[48]) != len(payload)-cursorHeaderBytes {
		return "", ErrInvalidCursor
	}
	binding, err := codec.binding(subject, query, now)
	if err != nil || !hmac.Equal(binding, payload[16:48]) {
		return "", ErrInvalidCursor
	}
	issued := time.UnixMicro(int64(binary.BigEndian.Uint64(payload[:8]))).UTC()
	expires := time.UnixMicro(int64(binary.BigEndian.Uint64(payload[8:16]))).UTC()
	position := payload[cursorHeaderBytes:]
	if query.AssumableRoles != nil {
		protector, err := codec.positionCipher(binding)
		if err != nil {
			return "", ErrInvalidCursor
		}
		position, err = protector.Open(nil, nil, position, roleDiscoveryCursorAAD(binding))
		if err != nil {
			return "", ErrInvalidCursor
		}
		defer clear(position)
	}
	after := string(position)
	if issued.After(now) || !now.Before(expires) || !issued.Before(expires) ||
		expires.Sub(issued) > cursorLifetime || expires.After(subject.Session.ExpiresAt) ||
		iamv1.ValidateID("after", after) != nil {
		return "", ErrInvalidCursor
	}
	return after, nil
}

// Sparse self discovery can continue after a role that was not disclosed.
// MAC alone would reveal that ID. Derive a purpose/snapshot-specific AES key
// from the existing sealed cursor key; keep its envelope and binding owner.
func (codec CursorCodec) positionCipher(binding []byte) (cipher.AEAD, error) {
	digest := hmac.New(sha256.New, codec.key[:])
	digest.Write([]byte("matrix.iam.directory.cursor.private-position.v1\x00"))
	digest.Write(binding)
	key := digest.Sum(nil)
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func roleDiscoveryCursorAAD(binding []byte) []byte {
	return append([]byte("matrix.iam.assumable-roles.cursor.ir1\x00"), binding...)
}

func (codec CursorCodec) tag(payload []byte) []byte {
	digest := hmac.New(sha256.New, codec.key[:])
	digest.Write([]byte("matrix.iam.directory.cursor.tag.v1\x00"))
	digest.Write(payload)
	return digest.Sum(nil)
}

func (codec CursorCodec) binding(subject SubjectContext, query DirectoryQuery, now time.Time) ([]byte, error) {
	if validateSubjectContext(subject, now) != nil || subject.Principal.Type != iamv1.PrincipalUser ||
		(subject.Principal.MustChangePassword && query.LoginSessions == nil) || iamv1.ValidateID("installationId", query.InstallationID) != nil ||
		(subject.InstallationID != "" && subject.InstallationID != query.InstallationID) {
		return nil, ErrInvalidCursor
	}
	validQuery := false
	var mode iamv1.AuthorizationResourceMode
	var usage iamv1.AuthorizationCollectionUsage
	pageSize := iamv1.DirectoryPageSize
	if query.LoginSessions != nil {
		validQuery = query.AssumableRoles == nil && query.RoleSessions == nil && query.Action == "" && query.Resource == (iamv1.ResourceReference{}) &&
			query.LoginSessions.CredentialGeneration > 0 && query.LoginSessions.CredentialGeneration <= 9007199254740991
	} else if query.AssumableRoles != nil {
		revision := query.AssumableRoles
		validQuery = query.RoleSessions == nil && query.Action == "" && query.Resource == (iamv1.ResourceReference{}) &&
			revision.CredentialGeneration > 0 && revision.CredentialGeneration <= 9007199254740991 &&
			revision.DirectoryRevision > 0 && revision.DirectoryRevision <= 9007199254740991
		pageSize = iamv1.RoleDiscoveryPageSize
	} else if query.RoleSessions != nil {
		filter, err := iamv1.NormalizeRoleSessionFilter(query.RoleSessions.Filter)
		validQuery = err == nil && filter == query.RoleSessions.Filter && ValidateRoleSessionDirectoryRevision(query.RoleSessions.Revision) == nil &&
			query.Action == iamv1.ActionIAMRoleSessionList && query.Resource.Kind == iamv1.ResourceRole && iamv1.ValidateID("roleId", query.Resource.ID) == nil
		mode = iamv1.AuthorizationResourceInstance
	} else {
		switch query.Action {
		case iamv1.ActionIAMUserList, iamv1.ActionIAMGroupList, iamv1.ActionIAMRoleList:
			validQuery = query.Resource == (iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: string(subject.Organization.ID)})
			mode = iamv1.AuthorizationResourceInstance
		case iamv1.ActionIAMAccountRead:
			validQuery = query.Resource == (iamv1.ResourceReference{Kind: iamv1.ResourceAccount, ID: "collection"})
			mode, usage = iamv1.AuthorizationResourceCollection, iamv1.AuthorizationCollectionList
		case iamv1.ActionIAMGroupMembershipList:
			validQuery = query.Resource.Kind == iamv1.ResourceGroup && iamv1.ValidateID("groupId", query.Resource.ID) == nil
			mode = iamv1.AuthorizationResourceInstance
		case iamv1.ActionIAMRoleRead:
			validQuery = query.Resource.Kind == iamv1.ResourceRole && iamv1.ValidateID("roleId", query.Resource.ID) == nil
			mode = iamv1.AuthorizationResourceInstance
		}
	}
	if !validQuery {
		return nil, ErrInvalidCursor
	}
	if query.AssumableRoles == nil && query.LoginSessions == nil {
		request, err := iamv1.NewAuthorizationRequest(query.Action, query.Resource, mode, usage, "cursor-authorization", "cursor-authorization")
		if err != nil {
			return nil, ErrInvalidCursor
		}
		evaluation, err := Decide(subject, iamv1.ServiceIAM, request, "cursor-authorization", now)
		if err != nil || !evaluation.Allowed {
			return nil, ErrInvalidCursor
		}
	}
	// Include every live source, not just the matching Allow. Removal of one
	// source while another still allows, or restoring a default version pointer,
	// must not resurrect a cursor from the previous authority revision.
	type sourceRevision struct {
		AttachmentID      iamv1.PolicyAttachmentID
		AttachmentVersion uint64
		PolicyID          iamv1.PolicyID
		PolicyRevision    uint64
		DefaultVersionID  iamv1.PolicyVersionID
		ContentDigest     string
		Membership        *iamv1.GroupMembership
	}
	sources := make([]sourceRevision, 0, len(subject.Policies))
	for _, row := range subject.Policies {
		sources = append(sources, sourceRevision{row.Attachment.ID, row.Attachment.ResourceVersion,
			row.Policy.ID, row.Policy.ResourceVersion, row.Version.ID, row.Version.ContentDigest, row.Membership})
	}
	slices.SortFunc(sources, func(left, right sourceRevision) int { return cmp.Compare(left.AttachmentID, right.AttachmentID) })
	type boundaryRevision struct {
		State          string
		ID             string
		Revision       uint64
		PolicyRevision uint64
		Version        *iamv1.PolicyVersionReference
	}
	boundary := boundaryRevision{State: subject.Boundary.State, ID: subject.Boundary.BoundaryID, Revision: subject.Boundary.ResourceVersion}
	if subject.Boundary.Policy != nil {
		boundary.PolicyRevision = subject.Boundary.Policy.ResourceVersion
		boundary.Version = &iamv1.PolicyVersionReference{PolicyID: subject.Boundary.Policy.ID, VersionID: subject.Boundary.Version.ID, ContentDigest: subject.Boundary.Version.ContentDigest}
	}
	projection := struct {
		InstallationID   string
		AccountID        iamv1.AccountID
		AccountRevision  uint64
		PrincipalID      iamv1.PrincipalID
		PrincipalVersion uint64
		Session          iamv1.Session
		Query            DirectoryQuery
		Order            string
		PageSize         int
		Sources          []sourceRevision
		Boundary         boundaryRevision
	}{query.InstallationID, subject.Organization.ID, subject.Organization.ResourceVersion,
		subject.Principal.ID, subject.Principal.ResourceVersion, subject.Session, query, "id:asc", pageSize, sources, boundary}
	encoded, err := json.Marshal(projection)
	if err != nil {
		return nil, ErrInvalidCursor
	}
	defer clear(encoded)
	digest := hmac.New(sha256.New, codec.key[:])
	digest.Write([]byte("matrix.iam.directory.cursor.binding.v1\x00"))
	digest.Write(encoded)
	return digest.Sum(nil), nil
}
