package localmachine

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/runnerenrollment"
	"github.com/xiak/matrix/app/service/installation/internal/runnernodecommand"
	"github.com/xiak/matrix/app/service/installation/release"
	"github.com/xiak/matrix/app/service/installation/topology"
	"github.com/xiak/matrix/app/service/internal/processconfig"
)

const (
	maximumRunnerRequest = 128 * 1024
	maximumEnrollment    = 256 * 1024
)

var _ runnernodecommand.Effects = (*Effects)(nil)

func (effects *Effects) AuthenticateRunnerRelease(
	ctx context.Context,
	root string,
	trustPath string,
) (release.VerifiedBundle, error) {
	if effects == nil || ctx == nil {
		return release.VerifiedBundle{}, runnernodecommand.ErrEffectUnavailable
	}
	if err := ctx.Err(); err != nil {
		return release.VerifiedBundle{}, err
	}
	trustBytes, _, err := release.ReadTrustRootFile(trustPath)
	if err != nil {
		return release.VerifiedBundle{}, errors.Join(runnernodecommand.ErrEffectVerification, err)
	}
	defer clear(trustBytes)
	bundle, err := release.VerifyRunnerDirectory(root, trustBytes)
	if err != nil {
		return release.VerifiedBundle{}, errors.Join(runnernodecommand.ErrEffectVerification, err)
	}
	return bundle, nil
}

func (effects *Effects) ExportRunnerRelease(
	ctx context.Context,
	plan runnernodecommand.ExportReleasePlan,
) (runnerenrollment.AuthorityPins, error) {
	if effects == nil || ctx == nil || len(plan.TrustBytes) == 0 {
		return runnerenrollment.AuthorityPins{}, runnernodecommand.ErrEffectUnavailable
	}
	if err := ctx.Err(); err != nil {
		return runnerenrollment.AuthorityPins{}, err
	}
	pins, err := readRunnerAuthorityPins(plan.Root, plan.InstallationID)
	if err != nil {
		return runnerenrollment.AuthorityPins{}, errors.Join(
			runnernodecommand.ErrEffectVerification, err,
		)
	}
	if existing, err := release.VerifyRunnerDirectory(plan.Output, plan.TrustBytes); err == nil {
		if existing.ManifestSHA256 == plan.Bundle.ManifestSHA256 &&
			existing.Manifest.Release.ID == plan.Bundle.Manifest.Release.ID {
			return pins, nil
		}
		return runnerenrollment.AuthorityPins{}, runnernodecommand.ErrEffectConflict
	} else if _, statErr := os.Lstat(plan.Output); !errors.Is(statErr, os.ErrNotExist) {
		return runnerenrollment.AuthorityPins{}, errors.Join(runnernodecommand.ErrEffectConflict, err)
	}
	err = publishPrivateDirectory(plan.Output, func(staging string) error {
		for _, name := range []string{release.ManifestFilename, release.SignatureFilename} {
			content, err := processconfig.ReadFile(
				filepath.Join(plan.Bundle.Root, name), 1024*1024, false,
			)
			if err != nil {
				return errors.Join(runnernodecommand.ErrEffectVerification, err)
			}
			if err := writePrivateFile(filepath.Join(staging, name), content, false); err != nil {
				clear(content)
				return err
			}
			clear(content)
		}
		for _, relative := range release.RunnerReleasePayloadPaths() {
			if err := copyVerifiedRunnerPayload(plan.Bundle, relative, staging); err != nil {
				return err
			}
		}
		verified, err := release.VerifyRunnerDirectory(staging, plan.TrustBytes)
		if err != nil || verified.ManifestSHA256 != plan.Bundle.ManifestSHA256 {
			return errors.Join(runnernodecommand.ErrEffectVerification, err)
		}
		return nil
	})
	if err != nil {
		return runnerenrollment.AuthorityPins{}, err
	}
	return pins, nil
}

func (effects *Effects) CreateRunnerRequest(
	ctx context.Context,
	plan runnernodecommand.CreateRequestPlan,
) (runnerenrollment.Request, error) {
	if effects == nil || effects.entropy == nil || ctx == nil {
		return runnerenrollment.Request{}, runnernodecommand.ErrEffectUnavailable
	}
	if err := ctx.Err(); err != nil {
		return runnerenrollment.Request{}, err
	}
	if existing, err := readExistingRunnerRequest(plan.Root); err == nil {
		if existing.ReleaseID == plan.Bundle.Manifest.Release.ID &&
			existing.InstallationID == plan.InstallationID && existing.NodeID == plan.NodeID &&
			existing.GatewayOrigin == plan.GatewayOrigin && len(existing.Slots) == int(plan.Slots) &&
			existing.AuthorityPins == plan.AuthorityPins &&
			validateStoredRunnerKeys(plan.Root, existing) == nil {
			return existing, nil
		}
		return runnerenrollment.Request{}, runnernodecommand.ErrEffectConflict
	} else if _, statErr := os.Lstat(plan.Root); !errors.Is(statErr, os.ErrNotExist) {
		return runnerenrollment.Request{}, errors.Join(runnernodecommand.ErrEffectConflict, err)
	}

	keys := make([][]byte, plan.Slots)
	slots := make([]runnerenrollment.SlotRequest, plan.Slots)
	for index := range slots {
		if err := ctx.Err(); err != nil {
			clearRunnerKeys(keys)
			return runnerenrollment.Request{}, err
		}
		slot := uint8(index + 1)
		identity := runnerenrollment.SlotIdentity(plan.InstallationID, plan.NodeID, slot)
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), effects.entropy)
		if err != nil {
			clearRunnerKeys(keys)
			return runnerenrollment.Request{}, errors.Join(runnernodecommand.ErrEffectUnavailable, err)
		}
		uri, err := url.Parse(identity)
		if err != nil {
			clearRunnerKeys(keys)
			return runnerenrollment.Request{}, errors.Join(runnernodecommand.ErrEffectVerification, err)
		}
		csr, err := x509.CreateCertificateRequest(effects.entropy, &x509.CertificateRequest{
			Subject: runnerenrollment.SlotCertificateSubject(plan.NodeID, slot),
			URIs:    []*url.URL{uri}, SignatureAlgorithm: x509.ECDSAWithSHA256,
		}, privateKey)
		if err != nil {
			clearRunnerKeys(keys)
			return runnerenrollment.Request{}, errors.Join(runnernodecommand.ErrEffectUnavailable, err)
		}
		encodedKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			clearRunnerKeys(keys)
			return runnerenrollment.Request{}, errors.Join(runnernodecommand.ErrEffectVerification, err)
		}
		keys[index] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey})
		slots[index] = runnerenrollment.SlotRequest{Index: slot, Identity: identity, CSR: csr}
	}
	defer clearRunnerKeys(keys)
	request, err := runnerenrollment.NewRequest(
		plan.Bundle.Manifest.Release.ID, plan.InstallationID, plan.NodeID,
		plan.GatewayOrigin, plan.AuthorityPins, slots,
	)
	if err != nil {
		return runnerenrollment.Request{}, errors.Join(runnernodecommand.ErrEffectVerification, err)
	}
	requestBytes, err := runnerenrollment.EncodeRequest(request)
	if err != nil {
		return runnerenrollment.Request{}, errors.Join(runnernodecommand.ErrEffectVerification, err)
	}
	defer clear(requestBytes)
	err = publishPrivateDirectory(plan.Root, func(staging string) error {
		if err := writePrivateFile(
			filepath.Join(staging, runnernodecommand.EnrollmentRequestFilename), requestBytes, false,
		); err != nil {
			return err
		}
		for index, key := range keys {
			slotName := strconv.Itoa(index + 1)
			secretDirectory := filepath.Join(staging, "secrets", "slots", slotName)
			dataRoot := filepath.Join(staging, "data", "slots", slotName)
			for _, directory := range []string{
				secretDirectory, filepath.Join(dataRoot, "journal"),
				filepath.Join(dataRoot, "workspace"),
			} {
				if err := makePrivateDirectory(directory); err != nil {
					return err
				}
			}
			if err := writePrivateFile(
				filepath.Join(secretDirectory, "client.key"), key, false,
			); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return runnerenrollment.Request{}, err
	}
	return request, nil
}

func (effects *Effects) ReadRunnerRequest(
	ctx context.Context,
	path string,
) (runnerenrollment.Request, error) {
	if effects == nil || ctx == nil {
		return runnerenrollment.Request{}, runnernodecommand.ErrEffectUnavailable
	}
	if err := ctx.Err(); err != nil {
		return runnerenrollment.Request{}, err
	}
	content, err := processconfig.ReadFile(path, maximumRunnerRequest, false)
	if err != nil {
		return runnerenrollment.Request{}, errors.Join(runnernodecommand.ErrEffectInput, err)
	}
	defer clear(content)
	request, err := runnerenrollment.DecodeRequest(content)
	if err != nil {
		return runnerenrollment.Request{}, errors.Join(runnernodecommand.ErrEffectVerification, err)
	}
	return request, nil
}

func (effects *Effects) ReadRunnerEnrollment(
	ctx context.Context,
	path string,
) (runnerenrollment.SignedEnrollment, error) {
	if effects == nil || ctx == nil {
		return runnerenrollment.SignedEnrollment{}, runnernodecommand.ErrEffectUnavailable
	}
	if err := ctx.Err(); err != nil {
		return runnerenrollment.SignedEnrollment{}, err
	}
	content, err := processconfig.ReadFile(path, maximumEnrollment, false)
	if err != nil {
		return runnerenrollment.SignedEnrollment{}, errors.Join(runnernodecommand.ErrEffectInput, err)
	}
	defer clear(content)
	enrollment, err := runnerenrollment.DecodeSignedEnrollment(content)
	if err != nil {
		return runnerenrollment.SignedEnrollment{}, errors.Join(runnernodecommand.ErrEffectVerification, err)
	}
	return enrollment, nil
}

func (effects *Effects) EnrollRunner(
	ctx context.Context,
	plan runnernodecommand.EnrollPlan,
) (runnerenrollment.SignedEnrollment, error) {
	if effects == nil || effects.entropy == nil || ctx == nil ||
		runnerenrollment.ValidateRequest(plan.Request) != nil ||
		plan.Request.InstallationID != plan.InstallationID ||
		plan.Request.ReleaseID != plan.Bundle.Manifest.Release.ID {
		return runnerenrollment.SignedEnrollment{}, runnernodecommand.ErrEffectInput
	}
	if err := ctx.Err(); err != nil {
		return runnerenrollment.SignedEnrollment{}, err
	}
	record := filepath.Join(
		filepath.FromSlash(layout.DevOpsRunnerEnrollmentRoot),
		plan.Request.NodeID+".json",
	)
	if exists, err := managedFileExists(plan.Root, record); err != nil {
		return runnerenrollment.SignedEnrollment{}, errors.Join(runnernodecommand.ErrEffectConflict, err)
	} else if exists {
		content, err := readManagedFile(plan.Root, record, maximumEnrollment)
		if err != nil {
			return runnerenrollment.SignedEnrollment{}, errors.Join(runnernodecommand.ErrEffectVerification, err)
		}
		defer clear(content)
		signed, err := runnerenrollment.DecodeSignedEnrollment(content)
		if err != nil || runnerenrollment.ValidateEnrollmentAgainstRequest(signed, plan.Request) != nil {
			return runnerenrollment.SignedEnrollment{}, errors.Join(runnernodecommand.ErrEffectConflict, err)
		}
		if err := writeExternalEnrollment(plan.Output, content); err != nil {
			return runnerenrollment.SignedEnrollment{}, err
		}
		return signed, nil
	}

	bundleContent, err := readManagedFile(
		plan.Root, filepath.FromSlash(layout.DevOpsExecutorPKIBundle), maximumExecutorPKI,
	)
	if err != nil {
		return runnerenrollment.SignedEnrollment{}, errors.Join(runnernodecommand.ErrEffectVerification, err)
	}
	defer clear(bundleContent)
	pki, err := decodeExecutorPKIBundle(bundleContent, plan.InstallationID)
	if err != nil {
		return runnerenrollment.SignedEnrollment{}, errors.Join(runnernodecommand.ErrEffectVerification, err)
	}
	defer pki.clear()
	pins, err := runnerenrollment.NewAuthorityPins(
		pki.ServerAuthority.Certificate, pki.RunnerAuthority.Certificate,
	)
	if err != nil || pins != plan.Request.AuthorityPins {
		return runnerenrollment.SignedEnrollment{}, runnernodecommand.ErrEffectVerification
	}
	runnerCA, runnerKey, err := executorAuthority(pki.RunnerAuthority)
	if err != nil {
		return runnerenrollment.SignedEnrollment{}, errors.Join(runnernodecommand.ErrEffectVerification, err)
	}
	requestDigest, _ := runnerenrollment.RequestDigest(plan.Request)
	document := runnerenrollment.EnrollmentDocument{
		APIVersion: runnerenrollment.APIVersion, Kind: runnerenrollment.SignedEnrollmentKind,
		RequestDigest: requestDigest, ReleaseID: plan.Request.ReleaseID,
		InstallationID: plan.InstallationID, NodeID: plan.Request.NodeID,
		GatewayOrigin:     plan.Request.GatewayOrigin,
		GatewayServerName: topology.DevOpsExecutorGatewayServerName,
		RunnerNamespace:   plan.Request.RunnerNamespace,
		ServerCA:          append([]byte(nil), pki.ServerAuthority.Certificate...),
		RunnerCA:          append([]byte(nil), pki.RunnerAuthority.Certificate...),
		Slots:             make([]runnerenrollment.IssuedSlot, len(plan.Request.Slots)),
	}
	for index, slot := range plan.Request.Slots {
		certificate, err := issueRunnerCertificate(
			pki, runnerCA, runnerKey, plan.Request.NodeID, slot, effects.entropy,
		)
		if err != nil {
			return runnerenrollment.SignedEnrollment{}, err
		}
		document.Slots[index] = runnerenrollment.IssuedSlot{
			Index: slot.Index, Identity: slot.Identity, Certificate: certificate,
		}
	}
	signed, err := runnerenrollment.NewSignedEnrollment(document, runnerKey, effects.entropy)
	if err != nil {
		return runnerenrollment.SignedEnrollment{}, errors.Join(runnernodecommand.ErrEffectVerification, err)
	}
	encoded, err := runnerenrollment.EncodeSignedEnrollment(signed)
	if err != nil {
		return runnerenrollment.SignedEnrollment{}, errors.Join(runnernodecommand.ErrEffectVerification, err)
	}
	defer clear(encoded)
	if err := writeManagedOnce(plan.Root, record, encoded); err != nil {
		return runnerenrollment.SignedEnrollment{}, errors.Join(runnernodecommand.ErrEffectConflict, err)
	}
	if err := writeExternalEnrollment(plan.Output, encoded); err != nil {
		return runnerenrollment.SignedEnrollment{}, err
	}
	return signed, nil
}

func issueRunnerCertificate(
	bundle executorPKIBundle,
	authority *x509.Certificate,
	authorityKey *ecdsa.PrivateKey,
	nodeID string,
	slot runnerenrollment.SlotRequest,
	entropy io.Reader,
) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(slot.CSR)
	if err != nil || csr.CheckSignature() != nil || authority == nil || authorityKey == nil {
		return nil, runnernodecommand.ErrEffectVerification
	}
	publicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, runnernodecommand.ErrEffectVerification
	}
	identity, err := url.Parse(slot.Identity)
	if err != nil {
		return nil, runnernodecommand.ErrEffectVerification
	}
	keyID, err := executorKeyID(publicKey)
	if err != nil {
		return nil, errors.Join(runnernodecommand.ErrEffectVerification, err)
	}
	role := "runner-" + nodeID + "-slot-" + strconv.Itoa(int(slot.Index))
	template := &x509.Certificate{
		SerialNumber: executorCertificateSerial(bundle.InstallationID, role, bundle.IssuedAt),
		Subject:      runnerenrollment.SlotCertificateSubject(nodeID, slot.Index),
		NotBefore:    bundle.NotBefore, NotAfter: bundle.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, SubjectKeyId: keyID,
		AuthorityKeyId: append([]byte(nil), authority.SubjectKeyId...),
		URIs:           []*url.URL{identity},
	}
	encoded, err := x509.CreateCertificate(
		entropy, template, authority, publicKey, authorityKey,
	)
	if err != nil {
		return nil, errors.Join(runnernodecommand.ErrEffectUnavailable, err)
	}
	return append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded}),
		bundle.RunnerAuthority.Certificate...,
	), nil
}

func executorAuthority(pair executorKeyPair) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	keyPair, err := tls.X509KeyPair(pair.Certificate, pair.PrivateKey)
	if err != nil || len(keyPair.Certificate) != 1 {
		return nil, nil, errors.New("executor authority is invalid")
	}
	certificate, err := x509.ParseCertificate(keyPair.Certificate[0])
	privateKey, ok := keyPair.PrivateKey.(*ecdsa.PrivateKey)
	if err != nil || !ok || privateKey.Curve != elliptic.P256() {
		return nil, nil, errors.New("executor authority is invalid")
	}
	return certificate, privateKey, nil
}

func readRunnerAuthorityPins(root, installationID string) (runnerenrollment.AuthorityPins, error) {
	content, err := readManagedFile(
		root, filepath.FromSlash(layout.DevOpsExecutorPKIBundle), maximumExecutorPKI,
	)
	if err != nil {
		return runnerenrollment.AuthorityPins{}, err
	}
	defer clear(content)
	pki, err := decodeExecutorPKIBundle(content, installationID)
	if err != nil {
		return runnerenrollment.AuthorityPins{}, err
	}
	defer pki.clear()
	return runnerenrollment.NewAuthorityPins(
		pki.ServerAuthority.Certificate, pki.RunnerAuthority.Certificate,
	)
}

func readExistingRunnerRequest(root string) (runnerenrollment.Request, error) {
	if err := validateRunnerNodeRoot(root); err != nil {
		return runnerenrollment.Request{}, err
	}
	content, err := processconfig.ReadFile(
		filepath.Join(root, runnernodecommand.EnrollmentRequestFilename), maximumRunnerRequest, false,
	)
	if err != nil {
		return runnerenrollment.Request{}, err
	}
	defer clear(content)
	return runnerenrollment.DecodeRequest(content)
}

func validateStoredRunnerKeys(root string, request runnerenrollment.Request) error {
	for _, slot := range request.Slots {
		path := filepath.Join(
			root, "secrets", "slots", strconv.Itoa(int(slot.Index)), "client.key",
		)
		content, err := processconfig.ReadFile(path, 16*1024, true)
		if err != nil {
			return err
		}
		block, rest := pem.Decode(content)
		if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 ||
			len(rest) != 0 || !bytes.Equal(content, pem.EncodeToMemory(block)) {
			clear(content)
			return errors.New("stored runner private key is invalid")
		}
		parsed, keyErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		key, keyOK := parsed.(*ecdsa.PrivateKey)
		csr, csrErr := x509.ParseCertificateRequest(slot.CSR)
		if keyErr != nil || !keyOK || key.Curve != elliptic.P256() || csrErr != nil ||
			!samePublicKey(&key.PublicKey, csr.PublicKey) {
			clear(content)
			return errors.New("stored runner private key does not match its request")
		}
		clear(content)
	}
	return nil
}

func samePublicKey(left, right any) bool {
	leftBytes, leftErr := x509.MarshalPKIXPublicKey(left)
	rightBytes, rightErr := x509.MarshalPKIXPublicKey(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func clearRunnerKeys(keys [][]byte) {
	for _, key := range keys {
		clear(key)
	}
}

func copyVerifiedRunnerPayload(
	bundle release.VerifiedBundle,
	relative string,
	targetRoot string,
) error {
	source, declaration, err := bundle.OpenVerifiedPayload(relative)
	if err != nil {
		return errors.Join(runnernodecommand.ErrEffectVerification, err)
	}
	defer source.Close()
	target := filepath.Join(targetRoot, filepath.FromSlash(relative))
	if err := makePrivateDirectory(filepath.Dir(target)); err != nil {
		return err
	}
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.Join(runnernodecommand.ErrEffectUnavailable, err)
	}
	succeeded := false
	defer func() {
		_ = output.Close()
		if !succeeded {
			_ = os.Remove(target)
		}
	}()
	mode := os.FileMode(0o600)
	if declaration.Executable {
		mode = 0o700
	}
	if err := os.Chmod(target, mode); err != nil {
		return errors.Join(runnernodecommand.ErrEffectUnavailable, err)
	}
	written, copyErr := io.Copy(output, io.LimitReader(source, int64(declaration.Size)+1))
	if copyErr != nil || written != int64(declaration.Size) || output.Sync() != nil ||
		output.Close() != nil {
		return runnernodecommand.ErrEffectUnavailable
	}
	succeeded = true
	return nil
}

func publishPrivateDirectory(target string, populate func(string) error) error {
	if target == "" || !filepath.IsAbs(target) || filepath.Clean(target) != target ||
		populate == nil {
		return runnernodecommand.ErrEffectInput
	}
	parent := filepath.Dir(target)
	info, err := validateManagedExistingPath(parent)
	if err != nil || !info.IsDir() {
		return errors.Join(runnernodecommand.ErrEffectInput, err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		return runnernodecommand.ErrEffectConflict
	}
	staging, err := os.MkdirTemp(parent, ".matrix-runner-")
	if err != nil {
		return errors.Join(runnernodecommand.ErrEffectUnavailable, err)
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = os.RemoveAll(staging)
		}
	}()
	if err := protectManagedPath(staging, true); err != nil {
		return errors.Join(runnernodecommand.ErrEffectUnavailable, err)
	}
	if err := populate(staging); err != nil {
		return err
	}
	if err := os.Rename(staging, target); err != nil || syncManagedDirectory(parent) != nil {
		return errors.Join(runnernodecommand.ErrEffectOutcomeUnknown, err)
	}
	succeeded = true
	return nil
}

func makePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil || os.Chmod(path, 0o700) != nil {
		return runnernodecommand.ErrEffectUnavailable
	}
	return nil
}

func writePrivateFile(path string, content []byte, executable bool) error {
	if len(content) == 0 {
		return runnernodecommand.ErrEffectInput
	}
	if err := makePrivateDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if executable {
		mode = 0o700
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return errors.Join(runnernodecommand.ErrEffectUnavailable, err)
	}
	succeeded := false
	defer func() {
		_ = file.Close()
		if !succeeded {
			_ = os.Remove(path)
		}
	}()
	if err := os.Chmod(path, mode); err != nil ||
		writeAll(file, content) != nil || file.Sync() != nil || file.Close() != nil {
		return runnernodecommand.ErrEffectUnavailable
	}
	succeeded = true
	return nil
}

func writeExternalEnrollment(path string, content []byte) error {
	if existing, err := processconfig.ReadFile(path, maximumEnrollment, false); err == nil {
		defer clear(existing)
		if len(existing) == len(content) && subtle.ConstantTimeCompare(existing, content) == 1 {
			return nil
		}
		return runnernodecommand.ErrEffectConflict
	} else if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
		return errors.Join(runnernodecommand.ErrEffectConflict, err)
	}
	parent := filepath.Dir(path)
	info, err := validateManagedExistingPath(parent)
	if err != nil || !info.IsDir() {
		return errors.Join(runnernodecommand.ErrEffectInput, err)
	}
	if err := writePrivateFile(path, content, false); err != nil {
		return err
	}
	if err := syncManagedDirectory(parent); err != nil {
		return errors.Join(runnernodecommand.ErrEffectOutcomeUnknown, err)
	}
	return nil
}

func writeAll(target io.Writer, content []byte) error {
	for len(content) > 0 {
		written, err := target.Write(content)
		if err != nil {
			return err
		}
		content = content[written:]
	}
	return nil
}
