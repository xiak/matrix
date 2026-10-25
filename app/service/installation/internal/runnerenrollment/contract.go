// Package runnerenrollment owns the installation-bound CSR and certificate
// response exchanged between a dedicated DevOps runner node and the Matrix
// installation operator. Runner private keys never cross this contract.
package runnerenrollment

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/release"
	"github.com/xiak/matrix/app/service/installation/topology"
)

const (
	APIVersion             = "installation.matrix.xiak.com/v1"
	RequestKind            = "DevOpsRunnerEnrollmentRequest"
	SignedEnrollmentKind   = "DevOpsRunnerEnrollment"
	maximumRequestBytes    = 128 * 1024
	maximumEnrollmentBytes = 256 * 1024
	maximumPEMBytes        = 32 * 1024
)

var (
	nodeIDPattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{1,61}[a-z0-9]$`)
	releasePattern = regexp.MustCompile(`^matrix-v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]{0,63})?-[0-9a-f]{12}$`)
)

type Request struct {
	APIVersion      string        `json:"apiVersion"`
	Kind            string        `json:"kind"`
	ReleaseID       string        `json:"releaseId"`
	InstallationID  string        `json:"installationId"`
	NodeID          string        `json:"nodeId"`
	GatewayOrigin   string        `json:"gatewayOrigin"`
	RunnerNamespace string        `json:"runnerNamespace"`
	AuthorityPins   AuthorityPins `json:"authorityPins"`
	Slots           []SlotRequest `json:"slots"`
}

type AuthorityPins struct {
	ServerCAFingerprint string `json:"serverCAFingerprint"`
	RunnerCAFingerprint string `json:"runnerCAFingerprint"`
}

type SlotRequest struct {
	Index    uint8  `json:"index"`
	Identity string `json:"identity"`
	CSR      []byte `json:"csr"`
}

type EnrollmentDocument struct {
	APIVersion        string       `json:"apiVersion"`
	Kind              string       `json:"kind"`
	RequestDigest     string       `json:"requestDigest"`
	ReleaseID         string       `json:"releaseId"`
	InstallationID    string       `json:"installationId"`
	NodeID            string       `json:"nodeId"`
	GatewayOrigin     string       `json:"gatewayOrigin"`
	GatewayServerName string       `json:"gatewayServerName"`
	RunnerNamespace   string       `json:"runnerNamespace"`
	ServerCA          []byte       `json:"serverCA"`
	RunnerCA          []byte       `json:"runnerCA"`
	Slots             []IssuedSlot `json:"slots"`
}

type IssuedSlot struct {
	Index       uint8  `json:"index"`
	Identity    string `json:"identity"`
	Certificate []byte `json:"certificate"`
}

type SignedEnrollment struct {
	Document  EnrollmentDocument `json:"document"`
	Signature []byte             `json:"signature"`
}

func NewRequest(
	releaseID string,
	installationID string,
	nodeID string,
	gatewayOrigin string,
	authorityPins AuthorityPins,
	slots []SlotRequest,
) (Request, error) {
	request := Request{
		APIVersion: APIVersion, Kind: RequestKind, ReleaseID: releaseID,
		InstallationID: installationID, NodeID: nodeID, GatewayOrigin: gatewayOrigin,
		RunnerNamespace: topology.DevOpsRunnerNamespace(installationID),
		AuthorityPins:   authorityPins,
		Slots:           cloneSlotRequests(slots),
	}
	if err := ValidateRequest(request); err != nil {
		return Request{}, err
	}
	return request, nil
}

func ValidateRequest(request Request) error {
	if request.APIVersion != APIVersion || request.Kind != RequestKind ||
		!releasePattern.MatchString(request.ReleaseID) ||
		lifecycle.ValidateInstallationID(request.InstallationID) != nil ||
		!nodeIDPattern.MatchString(request.NodeID) ||
		ValidateGatewayOrigin(request.GatewayOrigin) != nil ||
		request.RunnerNamespace != topology.DevOpsRunnerNamespace(request.InstallationID) ||
		ValidateAuthorityPins(request.AuthorityPins) != nil ||
		len(request.Slots) == 0 || len(request.Slots) > int(release.RunnerMaximumSlots) {
		return errors.New("runner enrollment request identity is invalid")
	}
	for index, slot := range request.Slots {
		expectedIndex := uint8(index + 1)
		expectedIdentity := SlotIdentity(request.InstallationID, request.NodeID, expectedIndex)
		if slot.Index != expectedIndex || slot.Identity != expectedIdentity ||
			validateCSR(slot.CSR, request.NodeID, expectedIndex, expectedIdentity) != nil {
			return errors.New("runner enrollment request slot is invalid")
		}
	}
	return nil
}

func EncodeRequest(request Request) ([]byte, error) {
	if err := ValidateRequest(request); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(request)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumRequestBytes {
		return nil, errors.New("encode runner enrollment request failed")
	}
	return encoded, nil
}

func DecodeRequest(content []byte) (Request, error) {
	if len(content) == 0 || len(content) > maximumRequestBytes {
		return Request{}, errors.New("runner enrollment request size is invalid")
	}
	var request Request
	if err := decodeStrict(content, &request); err != nil {
		return Request{}, errors.New("runner enrollment request is invalid")
	}
	encoded, err := EncodeRequest(request)
	if err != nil || subtle.ConstantTimeCompare(encoded, content) != 1 {
		return Request{}, errors.New("runner enrollment request is not canonical")
	}
	return request, nil
}

func RequestDigest(request Request) (string, error) {
	encoded, err := EncodeRequest(request)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func NewSignedEnrollment(
	document EnrollmentDocument,
	signer *ecdsa.PrivateKey,
	entropy io.Reader,
) (SignedEnrollment, error) {
	if signer == nil || signer.Curve != elliptic.P256() || entropy == nil {
		return SignedEnrollment{}, errors.New("runner enrollment signer is invalid")
	}
	documentBytes, runnerCA, err := encodeEnrollmentDocument(document)
	if err != nil {
		return SignedEnrollment{}, err
	}
	if !publicKeysEqual(&signer.PublicKey, runnerCA.PublicKey) {
		return SignedEnrollment{}, errors.New("runner enrollment signer does not match its authority")
	}
	digest := sha256.Sum256(documentBytes)
	signature, err := ecdsa.SignASN1(entropy, signer, digest[:])
	if err != nil {
		return SignedEnrollment{}, errors.New("sign runner enrollment failed")
	}
	value := SignedEnrollment{Document: cloneEnrollmentDocument(document), Signature: signature}
	if err := ValidateSignedEnrollment(value); err != nil {
		return SignedEnrollment{}, err
	}
	return value, nil
}

func ValidateSignedEnrollment(value SignedEnrollment) error {
	documentBytes, runnerCA, err := encodeEnrollmentDocument(value.Document)
	if err != nil || len(value.Signature) == 0 || len(value.Signature) > 256 {
		return errors.New("signed runner enrollment is invalid")
	}
	publicKey, ok := runnerCA.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return errors.New("runner enrollment signing authority is invalid")
	}
	digest := sha256.Sum256(documentBytes)
	if !ecdsa.VerifyASN1(publicKey, digest[:], value.Signature) {
		return errors.New("runner enrollment signature is invalid")
	}
	return nil
}

func ValidateEnrollmentAgainstRequest(value SignedEnrollment, request Request) error {
	if ValidateRequest(request) != nil || ValidateSignedEnrollment(value) != nil {
		return errors.New("runner enrollment exchange is invalid")
	}
	document := value.Document
	requestDigest, _ := RequestDigest(request)
	authorityPins, authorityErr := NewAuthorityPins(document.ServerCA, document.RunnerCA)
	if document.RequestDigest != requestDigest || document.ReleaseID != request.ReleaseID ||
		document.InstallationID != request.InstallationID || document.NodeID != request.NodeID ||
		document.GatewayOrigin != request.GatewayOrigin ||
		document.RunnerNamespace != request.RunnerNamespace ||
		authorityErr != nil || authorityPins != request.AuthorityPins ||
		len(document.Slots) != len(request.Slots) {
		return errors.New("runner enrollment does not match its request")
	}
	for index := range request.Slots {
		csr, _ := x509.ParseCertificateRequest(request.Slots[index].CSR)
		leaf, _, err := parseIssuedCertificate(
			document.Slots[index].Certificate, document.RunnerCA,
		)
		if err != nil || !publicKeysEqual(csr.PublicKey, leaf.PublicKey) {
			return errors.New("runner enrollment certificate does not match its request")
		}
	}
	return nil
}

func EncodeSignedEnrollment(value SignedEnrollment) ([]byte, error) {
	if err := ValidateSignedEnrollment(value); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumEnrollmentBytes {
		return nil, errors.New("encode signed runner enrollment failed")
	}
	return encoded, nil
}

func DecodeSignedEnrollment(content []byte) (SignedEnrollment, error) {
	if len(content) == 0 || len(content) > maximumEnrollmentBytes {
		return SignedEnrollment{}, errors.New("signed runner enrollment size is invalid")
	}
	var value SignedEnrollment
	if err := decodeStrict(content, &value); err != nil {
		return SignedEnrollment{}, errors.New("signed runner enrollment is invalid")
	}
	encoded, err := EncodeSignedEnrollment(value)
	if err != nil || subtle.ConstantTimeCompare(encoded, content) != 1 {
		return SignedEnrollment{}, errors.New("signed runner enrollment is not canonical")
	}
	return value, nil
}

func SlotIdentity(installationID, nodeID string, slot uint8) string {
	return topology.DevOpsRunnerNamespace(installationID) + "/nodes/" + nodeID +
		"/slots/" + strconv.FormatUint(uint64(slot), 10)
}

func SlotCertificateSubject(nodeID string, slot uint8) pkix.Name {
	return pkix.Name{
		Organization: []string{"Matrix"},
		CommonName: "Matrix DevOps runner " + nodeID + " slot " +
			strconv.FormatUint(uint64(slot), 10),
	}
}

func ValidateGatewayOrigin(value string) error {
	origin, err := url.Parse(value)
	if err != nil || origin.Scheme != "https" || origin.Host == "" ||
		origin.User != nil || origin.Opaque != "" || origin.Path != "" ||
		origin.RawPath != "" || origin.RawQuery != "" || origin.ForceQuery ||
		origin.Fragment != "" || origin.Port() != "8444" || origin.String() != value {
		return errors.New("runner gateway origin is invalid")
	}
	host := origin.Hostname()
	if host == "" || strings.ToLower(host) != host {
		return errors.New("runner gateway host is invalid")
	}
	address := net.ParseIP(host)
	if address == nil || address.String() != host {
		return errors.New("runner gateway must be a canonical literal address")
	}
	return nil
}

func ValidateNodeID(value string) error {
	if !nodeIDPattern.MatchString(value) {
		return errors.New("runner node identity is invalid")
	}
	return nil
}

// NewAuthorityPins creates the node-side trust anchors that must be transferred
// from the installed platform over an operator-trusted channel before a CSR is
// created. The enrollment response cannot introduce or replace either anchor.
func NewAuthorityPins(serverCA, runnerCA []byte) (AuthorityPins, error) {
	server, serverErr := parseAuthority(serverCA)
	runner, runnerErr := parseAuthority(runnerCA)
	if serverErr != nil || runnerErr != nil ||
		bytes.Equal(server.RawSubjectPublicKeyInfo, runner.RawSubjectPublicKeyInfo) {
		return AuthorityPins{}, errors.New("runner enrollment authorities are invalid")
	}
	return AuthorityPins{
		ServerCAFingerprint: certificateFingerprint(server),
		RunnerCAFingerprint: certificateFingerprint(runner),
	}, nil
}

func ValidateAuthorityPins(value AuthorityPins) error {
	if !validDigest(value.ServerCAFingerprint) || !validDigest(value.RunnerCAFingerprint) ||
		value.ServerCAFingerprint == value.RunnerCAFingerprint {
		return errors.New("runner enrollment authority pins are invalid")
	}
	return nil
}

func encodeEnrollmentDocument(
	document EnrollmentDocument,
) ([]byte, *x509.Certificate, error) {
	runnerCA, serverCA, err := validateEnrollmentDocument(document)
	if err != nil {
		return nil, nil, err
	}
	if bytes.Equal(runnerCA.RawSubjectPublicKeyInfo, serverCA.RawSubjectPublicKeyInfo) {
		return nil, nil, errors.New("runner and server authorities overlap")
	}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumEnrollmentBytes {
		return nil, nil, errors.New("encode runner enrollment document failed")
	}
	return encoded, runnerCA, nil
}

func validateEnrollmentDocument(
	document EnrollmentDocument,
) (*x509.Certificate, *x509.Certificate, error) {
	if document.APIVersion != APIVersion || document.Kind != SignedEnrollmentKind ||
		!releasePattern.MatchString(document.ReleaseID) ||
		lifecycle.ValidateInstallationID(document.InstallationID) != nil ||
		!nodeIDPattern.MatchString(document.NodeID) ||
		ValidateGatewayOrigin(document.GatewayOrigin) != nil ||
		document.GatewayServerName != topology.DevOpsExecutorGatewayServerName ||
		document.RunnerNamespace != topology.DevOpsRunnerNamespace(document.InstallationID) ||
		!validDigest(document.RequestDigest) || len(document.Slots) == 0 ||
		len(document.Slots) > int(release.RunnerMaximumSlots) {
		return nil, nil, errors.New("runner enrollment document identity is invalid")
	}
	runnerCA, err := parseAuthority(document.RunnerCA)
	if err != nil {
		return nil, nil, errors.New("runner enrollment authority is invalid")
	}
	serverCA, err := parseAuthority(document.ServerCA)
	if err != nil {
		return nil, nil, errors.New("runner server authority is invalid")
	}
	for index, slot := range document.Slots {
		expectedIndex := uint8(index + 1)
		expectedIdentity := SlotIdentity(document.InstallationID, document.NodeID, expectedIndex)
		leaf, issuer, err := parseIssuedCertificate(slot.Certificate, document.RunnerCA)
		if slot.Index != expectedIndex || slot.Identity != expectedIdentity || err != nil ||
			!bytes.Equal(issuer.Raw, runnerCA.Raw) ||
			validateIssuedLeaf(leaf, runnerCA, document.NodeID, expectedIndex, expectedIdentity) != nil {
			return nil, nil, errors.New("runner enrollment issued slot is invalid")
		}
	}
	return runnerCA, serverCA, nil
}

func validateCSR(content []byte, nodeID string, slot uint8, identity string) error {
	if len(content) == 0 || len(content) > maximumPEMBytes {
		return errors.New("runner CSR size is invalid")
	}
	csr, err := x509.ParseCertificateRequest(content)
	publicKey, ok := csrPublicKey(csr)
	if err != nil || !ok || csr.CheckSignature() != nil ||
		csr.SignatureAlgorithm != x509.ECDSAWithSHA256 || publicKey.Curve != elliptic.P256() ||
		!subjectMatches(csr.RawSubject, SlotCertificateSubject(nodeID, slot)) ||
		len(csr.DNSNames) != 0 || len(csr.EmailAddresses) != 0 || len(csr.IPAddresses) != 0 ||
		len(csr.URIs) != 1 || csr.URIs[0].String() != identity || len(csr.Extensions) != 1 ||
		len(csr.ExtraExtensions) != 0 || len(csr.Attributes) != 1 {
		return errors.New("runner CSR is invalid")
	}
	return nil
}

func csrPublicKey(csr *x509.CertificateRequest) (*ecdsa.PublicKey, bool) {
	if csr == nil {
		return nil, false
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	return key, ok
}

func parseAuthority(content []byte) (*x509.Certificate, error) {
	blocks, err := certificateBlocks(content)
	if err != nil || len(blocks) != 1 {
		return nil, errors.New("certificate authority is invalid")
	}
	certificate, err := x509.ParseCertificate(blocks[0].Bytes)
	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if err != nil || !ok || publicKey.Curve != elliptic.P256() || !certificate.IsCA ||
		!certificate.BasicConstraintsValid || !certificate.MaxPathLenZero ||
		certificate.MaxPathLen != 0 ||
		certificate.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign ||
		certificate.CheckSignatureFrom(certificate) != nil {
		return nil, errors.New("certificate authority is invalid")
	}
	return certificate, nil
}

func parseIssuedCertificate(content, authority []byte) (*x509.Certificate, *x509.Certificate, error) {
	blocks, err := certificateBlocks(content)
	if err != nil || len(blocks) != 2 {
		return nil, nil, errors.New("runner certificate chain is invalid")
	}
	leaf, leafErr := x509.ParseCertificate(blocks[0].Bytes)
	issuer, issuerErr := x509.ParseCertificate(blocks[1].Bytes)
	if leafErr != nil || issuerErr != nil || !bytes.Equal(blocks[1].Bytes, authorityCertificateDER(authority)) {
		return nil, nil, errors.New("runner certificate chain is invalid")
	}
	return leaf, issuer, nil
}

func validateIssuedLeaf(
	leaf *x509.Certificate,
	issuer *x509.Certificate,
	nodeID string,
	slot uint8,
	identity string,
) error {
	if leaf == nil || issuer == nil || leaf.IsCA || !leaf.BasicConstraintsValid ||
		!subjectMatches(leaf.RawSubject, SlotCertificateSubject(nodeID, slot)) ||
		leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 1 ||
		leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		len(leaf.DNSNames) != 0 || len(leaf.EmailAddresses) != 0 ||
		len(leaf.IPAddresses) != 0 || len(leaf.URIs) != 1 ||
		leaf.URIs[0].String() != identity || leaf.CheckSignatureFrom(issuer) != nil ||
		leaf.NotBefore.Before(issuer.NotBefore) || leaf.NotAfter.After(issuer.NotAfter) {
		return errors.New("runner certificate is invalid")
	}
	return nil
}

func certificateBlocks(content []byte) ([]*pem.Block, error) {
	if len(content) == 0 || len(content) > maximumPEMBytes {
		return nil, errors.New("certificate PEM is invalid")
	}
	remaining := content
	blocks := make([]*pem.Block, 0, 2)
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 ||
			!bytes.HasPrefix(remaining, pem.EncodeToMemory(block)) {
			return nil, errors.New("certificate PEM is invalid")
		}
		blocks = append(blocks, block)
		remaining = rest
	}
	return blocks, nil
}

func authorityCertificateDER(content []byte) []byte {
	block, _ := pem.Decode(content)
	if block == nil {
		return nil
	}
	return block.Bytes
}

func publicKeysEqual(left, right any) bool {
	leftBytes, leftErr := x509.MarshalPKIXPublicKey(left)
	rightBytes, rightErr := x509.MarshalPKIXPublicKey(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func certificateFingerprint(certificate *x509.Certificate) string {
	digest := sha256.Sum256(certificate.Raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func subjectMatches(raw []byte, expected pkix.Name) bool {
	encoded, err := asn1.Marshal(expected.ToRDNSequence())
	return err == nil && bytes.Equal(raw, encoded)
}

func cloneSlotRequests(slots []SlotRequest) []SlotRequest {
	result := make([]SlotRequest, len(slots))
	for index, slot := range slots {
		result[index] = slot
		result[index].CSR = append([]byte(nil), slot.CSR...)
	}
	return result
}

func cloneEnrollmentDocument(document EnrollmentDocument) EnrollmentDocument {
	result := document
	result.ServerCA = append([]byte(nil), document.ServerCA...)
	result.RunnerCA = append([]byte(nil), document.RunnerCA...)
	result.Slots = make([]IssuedSlot, len(document.Slots))
	for index, slot := range document.Slots {
		result.Slots[index] = slot
		result.Slots[index].Certificate = append([]byte(nil), slot.Certificate...)
	}
	return result
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func decodeStrict(content []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("JSON has trailing content")
	}
	return nil
}
