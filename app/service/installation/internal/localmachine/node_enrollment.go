package localmachine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/xiak/matrix/api/contractjson"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/nodecommand"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
)

const (
	maximumStoredEnrollmentIntentBytes   = int64(64 * 1024)
	maximumStoredEnrollmentResponseBytes = 64 * 1024
	maximumStoredEnrollmentCleanupBytes  = int64(4 * 1024)
	enrollmentCleanupKind                = "NodeEnrollmentCleanup"
	enrollmentCleanupDiscard             = "DISCARD"
	enrollmentCleanupFinalize            = "FINALIZE"
)

type enrollmentCleanupMarker struct {
	APIVersion     string `json:"apiVersion"`
	Kind           string `json:"kind"`
	Mode           string `json:"mode"`
	IntentDigest   string `json:"intentDigest"`
	AttemptDigest  string `json:"attemptDigest"`
	ResponseDigest string `json:"responseDigest,omitempty"`
}

func (effects *NodeEffects) ResumeEnrollmentCleanup(root string) (bool, error) {
	relative := filepath.FromSlash(layout.NodeEnrollmentCleanup)
	exists, err := managedFileExists(root, relative)
	if err != nil {
		return false, nodecommand.ErrConflict
	}
	if !exists {
		return false, nil
	}
	source, err := readManagedFile(root, relative, maximumStoredEnrollmentCleanupBytes)
	if err != nil {
		return false, nodecommand.ErrVerification
	}
	defer clear(source)
	marker, err := decodeEnrollmentCleanupMarker(source)
	if err != nil {
		return false, nodecommand.ErrVerification
	}
	files := []enrollmentDigestFile{
		{filepath.FromSlash(layout.NodeEnrollmentIntent), maximumStoredEnrollmentIntentBytes, marker.IntentDigest},
		{filepath.FromSlash(layout.NodeEnrollmentAttempt), 128, marker.AttemptDigest},
	}
	if marker.ResponseDigest != "" {
		files = append(files, enrollmentDigestFile{
			filepath.FromSlash(layout.NodeEnrollmentResponse), maximumStoredEnrollmentResponseBytes, marker.ResponseDigest,
		})
	} else if responseExists, responseErr := managedFileExists(
		root, filepath.FromSlash(layout.NodeEnrollmentResponse),
	); responseErr != nil || responseExists {
		return false, nodecommand.ErrConflict
	}
	if err := validateEnrollmentDigestFiles(root, files); err != nil {
		return false, err
	}
	// The marker retains exact public digests across every removal. Delete the
	// private-key intent first; a crash can then resume exact cleanup without
	// making a surviving intent appear eligible for another raw exchange.
	for _, file := range files {
		if err := removeEnrollmentDigestFile(root, file); err != nil {
			return false, err
		}
	}
	if err := removeEnrollmentFile(root, enrollmentFile{relative: relative, expected: source}); err != nil {
		return false, err
	}
	return true, nil
}

func (effects *NodeEffects) ReadEnrollmentIntent(root string) (nodecommand.EnrollmentIntent, bool, error) {
	exists, err := managedFileExists(root, filepath.FromSlash(layout.NodeEnrollmentIntent))
	if err != nil {
		return nodecommand.EnrollmentIntent{}, false, nodecommand.ErrConflict
	}
	if !exists {
		return nodecommand.EnrollmentIntent{}, false, nil
	}
	source, err := readManagedFile(root, filepath.FromSlash(layout.NodeEnrollmentIntent), maximumStoredEnrollmentIntentBytes)
	if err != nil {
		return nodecommand.EnrollmentIntent{}, false, nodecommand.ErrVerification
	}
	defer clear(source)
	value, err := nodecommand.DecodeEnrollmentIntent(source)
	if err != nil {
		return nodecommand.EnrollmentIntent{}, false, nodecommand.ErrVerification
	}
	return value, true, nil
}

func (effects *NodeEffects) CreateEnrollmentIntent(root string, value nodecommand.EnrollmentIntent) error {
	encoded, err := nodecommand.EncodeEnrollmentIntent(value)
	if err != nil {
		return nodecommand.ErrVerification
	}
	defer clear(encoded)
	if err := writeManagedOnce(root, filepath.FromSlash(layout.NodeEnrollmentIntent), encoded); err != nil {
		return normalizeEnrollmentStoreError(err)
	}
	return nil
}

func (effects *NodeEffects) EnrollmentExchangeAttempted(root string, value nodecommand.EnrollmentIntent) (bool, error) {
	if nodecommand.ValidateEnrollmentIntent(value) != nil {
		return false, nodecommand.ErrVerification
	}
	relative := filepath.FromSlash(layout.NodeEnrollmentAttempt)
	exists, err := managedFileExists(root, relative)
	if err != nil {
		return false, nodecommand.ErrConflict
	}
	if !exists {
		return false, nil
	}
	expected := enrollmentAttemptBytes(value)
	actual, err := readManagedFile(root, relative, int64(len(expected)))
	equal := err == nil && subtle.ConstantTimeCompare(actual, expected) == 1
	clear(actual)
	if !equal {
		return false, nodecommand.ErrVerification
	}
	return true, nil
}

func (effects *NodeEffects) MarkEnrollmentExchangeAttempted(root string, value nodecommand.EnrollmentIntent) error {
	if nodecommand.ValidateEnrollmentIntent(value) != nil {
		return nodecommand.ErrVerification
	}
	if err := writeManagedOnce(root, filepath.FromSlash(layout.NodeEnrollmentAttempt), enrollmentAttemptBytes(value)); err != nil {
		return normalizeEnrollmentStoreError(err)
	}
	return nil
}

func (effects *NodeEffects) ReadEnrollmentResponse(
	root string,
	intent nodecommand.EnrollmentIntent,
) (paasv1.NodeEnrollmentExchangeResponse, bool, error) {
	relative := filepath.FromSlash(layout.NodeEnrollmentResponse)
	exists, err := managedFileExists(root, relative)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, false, nodecommand.ErrConflict
	}
	if !exists {
		return paasv1.NodeEnrollmentExchangeResponse{}, false, nil
	}
	source, err := readManagedFile(root, relative, maximumStoredEnrollmentResponseBytes)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, false, nodecommand.ErrVerification
	}
	defer clear(source)
	response, err := decodeEnrollmentResponse(intent, source)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, false, nodecommand.ErrVerification
	}
	return response, true, nil
}

func (effects *NodeEffects) CreateEnrollmentResponse(
	root string,
	intent nodecommand.EnrollmentIntent,
	response paasv1.NodeEnrollmentExchangeResponse,
) error {
	encoded, err := encodeEnrollmentResponse(intent, response)
	if err != nil {
		return nodecommand.ErrVerification
	}
	defer clear(encoded)
	if err := writeManagedOnce(root, filepath.FromSlash(layout.NodeEnrollmentResponse), encoded); err != nil {
		return normalizeEnrollmentStoreError(err)
	}
	return nil
}

func (effects *NodeEffects) DiscardEnrollmentIntent(root string, intent nodecommand.EnrollmentIntent) error {
	if nodecommand.ValidateEnrollmentIntent(intent) != nil {
		return nodecommand.ErrVerification
	}
	encoded, err := nodecommand.EncodeEnrollmentIntent(intent)
	if err != nil {
		return nodecommand.ErrVerification
	}
	defer clear(encoded)
	checks := []enrollmentFile{
		{filepath.FromSlash(layout.NodeEnrollmentIntent), encoded},
		{filepath.FromSlash(layout.NodeEnrollmentAttempt), enrollmentAttemptBytes(intent)},
	}
	if err := validateEnrollmentFiles(root, checks); err != nil {
		return err
	}
	if exists, err := managedFileExists(root, filepath.FromSlash(layout.NodeEnrollmentResponse)); err != nil || exists {
		return nodecommand.ErrConflict
	}
	return effects.beginEnrollmentCleanup(root, enrollmentCleanupDiscard, encoded, nil, enrollmentAttemptBytes(intent))
}

func (effects *NodeEffects) FinalizeEnrollment(
	root string,
	intent nodecommand.EnrollmentIntent,
	response paasv1.NodeEnrollmentExchangeResponse,
) error {
	intentBytes, err := nodecommand.EncodeEnrollmentIntent(intent)
	if err != nil {
		return nodecommand.ErrVerification
	}
	defer clear(intentBytes)
	responseBytes, err := encodeEnrollmentResponse(intent, response)
	if err != nil {
		return nodecommand.ErrVerification
	}
	defer clear(responseBytes)
	checks := []enrollmentFile{
		{filepath.FromSlash(layout.NodeEnrollmentIntent), intentBytes},
		{filepath.FromSlash(layout.NodeEnrollmentResponse), responseBytes},
		{filepath.FromSlash(layout.NodeEnrollmentAttempt), enrollmentAttemptBytes(intent)},
	}
	if err := validateEnrollmentFiles(root, checks); err != nil {
		return err
	}
	return effects.beginEnrollmentCleanup(
		root, enrollmentCleanupFinalize, intentBytes, responseBytes, enrollmentAttemptBytes(intent),
	)
}

func (effects *NodeEffects) CleanupRejectedEnrollment(
	ctx context.Context,
	plan nodecommand.Plan,
	intent nodecommand.EnrollmentIntent,
	response paasv1.NodeEnrollmentExchangeResponse,
) error {
	if effects == nil || ctx == nil || ctx.Err() != nil ||
		nodecommand.ValidateEnrollmentPlan(plan, intent, response) != nil {
		return nodecommand.ErrVerification
	}
	startup := nativeNodeStartup(plan)
	startupRelative, err := filepath.Rel(plan.Root, startup.unitFile)
	if err != nil || filepath.IsAbs(startupRelative) {
		return nodecommand.ErrVerification
	}
	files := []enrollmentFile{{startupRelative, nativeStartupUnit(startup)}}
	for _, file := range nodeCredentialFiles(plan) {
		files = append(files, enrollmentFile{filepath.FromSlash(file.name), file.content})
	}
	if err := validateEnrollmentFiles(plan.Root, files); err != nil {
		return err
	}
	for _, file := range files {
		if ctx.Err() != nil {
			return nodecommand.ErrOutcomeUnknown
		}
		if err := removeEnrollmentFile(plan.Root, file); err != nil {
			return err
		}
	}
	return effects.FinalizeEnrollment(plan.Root, intent, response)
}

type enrollmentFile struct {
	relative string
	expected []byte
}

type enrollmentDigestFile struct {
	relative string
	maximum  int64
	digest   string
}

func (effects *NodeEffects) beginEnrollmentCleanup(
	root string,
	mode string,
	intent []byte,
	response []byte,
	attempt []byte,
) error {
	marker := enrollmentCleanupMarker{
		APIVersion:    nodeconfig.APIVersion,
		Kind:          enrollmentCleanupKind,
		Mode:          mode,
		IntentDigest:  enrollmentFileDigest(intent),
		AttemptDigest: enrollmentFileDigest(attempt),
	}
	if len(response) != 0 {
		marker.ResponseDigest = enrollmentFileDigest(response)
	}
	encoded, err := encodeEnrollmentCleanupMarker(marker)
	if err != nil {
		return nodecommand.ErrVerification
	}
	defer clear(encoded)
	if err := writeManagedOnce(root, filepath.FromSlash(layout.NodeEnrollmentCleanup), encoded); err != nil {
		return normalizeEnrollmentStoreError(err)
	}
	resumed, err := effects.ResumeEnrollmentCleanup(root)
	if err != nil {
		return err
	}
	if !resumed {
		return nodecommand.ErrOutcomeUnknown
	}
	return nil
}

func encodeEnrollmentCleanupMarker(value enrollmentCleanupMarker) ([]byte, error) {
	if validateEnrollmentCleanupMarker(value) != nil {
		return nil, errors.New("node enrollment cleanup marker is invalid")
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > maximumStoredEnrollmentCleanupBytes {
		clear(encoded)
		return nil, errors.New("node enrollment cleanup marker cannot be encoded")
	}
	return encoded, nil
}

func decodeEnrollmentCleanupMarker(source []byte) (enrollmentCleanupMarker, error) {
	var value enrollmentCleanupMarker
	if contractjson.DecodeObjectBytes(source, maximumStoredEnrollmentCleanupBytes, &value) != nil ||
		validateEnrollmentCleanupMarker(value) != nil {
		return enrollmentCleanupMarker{}, errors.New("node enrollment cleanup marker is invalid")
	}
	canonical, err := encodeEnrollmentCleanupMarker(value)
	if err != nil || subtle.ConstantTimeCompare(canonical, source) != 1 {
		clear(canonical)
		return enrollmentCleanupMarker{}, errors.New("node enrollment cleanup marker is not canonical")
	}
	clear(canonical)
	return value, nil
}

func validateEnrollmentCleanupMarker(value enrollmentCleanupMarker) error {
	if value.APIVersion != nodeconfig.APIVersion || value.Kind != enrollmentCleanupKind ||
		(value.Mode != enrollmentCleanupDiscard && value.Mode != enrollmentCleanupFinalize) ||
		paasv1.ValidateDigest("intentDigest", value.IntentDigest) != nil ||
		paasv1.ValidateDigest("attemptDigest", value.AttemptDigest) != nil ||
		(value.Mode == enrollmentCleanupDiscard && value.ResponseDigest != "") ||
		(value.Mode == enrollmentCleanupFinalize && paasv1.ValidateDigest("responseDigest", value.ResponseDigest) != nil) {
		return errors.New("node enrollment cleanup marker metadata is invalid")
	}
	return nil
}

func enrollmentFileDigest(source []byte) string {
	digest := sha256.Sum256(source)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validateEnrollmentDigestFiles(root string, files []enrollmentDigestFile) error {
	for _, file := range files {
		if err := validateEnrollmentDigestFile(root, file); err != nil {
			return err
		}
	}
	return nil
}

func validateEnrollmentDigestFile(root string, file enrollmentDigestFile) error {
	path, err := managedPath(root, file.relative)
	if err != nil {
		return nodecommand.ErrConflict
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return nodecommand.ErrConflict
	}
	actual, err := readManagedFile(root, file.relative, file.maximum)
	equal := err == nil && enrollmentFileDigest(actual) == file.digest
	clear(actual)
	if !equal {
		return nodecommand.ErrConflict
	}
	return nil
}

func removeEnrollmentDigestFile(root string, file enrollmentDigestFile) error {
	if err := validateEnrollmentDigestFile(root, file); err != nil {
		return err
	}
	path, err := managedPath(root, file.relative)
	if err != nil {
		return nodecommand.ErrConflict
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return nodecommand.ErrConflict
	}
	if os.Remove(path) != nil || syncManagedDirectory(filepath.Dir(path)) != nil {
		return nodecommand.ErrOutcomeUnknown
	}
	return nil
}

func enrollmentAttemptBytes(value nodecommand.EnrollmentIntent) []byte {
	return []byte(value.Commitment + "\n")
}

func encodeEnrollmentResponse(
	intent nodecommand.EnrollmentIntent,
	response paasv1.NodeEnrollmentExchangeResponse,
) ([]byte, error) {
	if nodecommand.ValidateEnrollmentResponse(intent, response) != nil {
		return nil, errors.New("node enrollment response is invalid")
	}
	encoded, err := json.Marshal(response)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumStoredEnrollmentResponseBytes {
		clear(encoded)
		return nil, errors.New("node enrollment response cannot be encoded")
	}
	return encoded, nil
}

func decodeEnrollmentResponse(
	intent nodecommand.EnrollmentIntent,
	source []byte,
) (paasv1.NodeEnrollmentExchangeResponse, error) {
	var response paasv1.NodeEnrollmentExchangeResponse
	if contractjson.DecodeObjectBytes(source, maximumStoredEnrollmentResponseBytes, &response) != nil ||
		nodecommand.ValidateEnrollmentResponse(intent, response) != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, errors.New("node enrollment response is invalid")
	}
	canonical, err := json.Marshal(response)
	if err != nil || subtle.ConstantTimeCompare(canonical, source) != 1 {
		return paasv1.NodeEnrollmentExchangeResponse{}, errors.New("node enrollment response is not canonical")
	}
	return response, nil
}

func validateEnrollmentFiles(root string, files []enrollmentFile) error {
	for _, file := range files {
		path, err := managedPath(root, file.relative)
		if err != nil {
			return nodecommand.ErrConflict
		}
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nodecommand.ErrConflict
		}
		actual, err := readManagedFile(root, file.relative, int64(len(file.expected)))
		equal := err == nil && bytes.Equal(actual, file.expected)
		clear(actual)
		if !equal {
			return nodecommand.ErrConflict
		}
	}
	return nil
}

func removeEnrollmentFile(root string, file enrollmentFile) error {
	path, err := managedPath(root, file.relative)
	if err != nil {
		return nodecommand.ErrConflict
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return nodecommand.ErrConflict
	}
	actual, err := readManagedFile(root, file.relative, int64(len(file.expected)))
	equal := err == nil && bytes.Equal(actual, file.expected)
	clear(actual)
	if !equal {
		return nodecommand.ErrConflict
	}
	if os.Remove(path) != nil || syncManagedDirectory(filepath.Dir(path)) != nil {
		return nodecommand.ErrOutcomeUnknown
	}
	return nil
}

func normalizeEnrollmentStoreError(err error) error {
	switch {
	case errors.Is(err, errManagedConflict):
		return nodecommand.ErrConflict
	case errors.Is(err, errManagedOutcomeUnknown):
		return nodecommand.ErrOutcomeUnknown
	default:
		return nodecommand.ErrUnavailable
	}
}

var _ nodecommand.EnrollmentStore = (*NodeEffects)(nil)
