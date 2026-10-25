// matrix-platform exposes the installation-owned product discovery contract.
// It derives the installed product inventory only from the authenticated
// release manifest and enriches that inventory with live product readiness.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/productdiscovery"
	"github.com/xiak/matrix/app/service/installation/internal/productdiscovery/data/iamhttp"
	"github.com/xiak/matrix/app/service/installation/internal/productdiscovery/data/readinesshttp"
	producthttp "github.com/xiak/matrix/app/service/installation/internal/productdiscovery/service/nethttp"
	"github.com/xiak/matrix/app/service/installation/release"
	"github.com/xiak/matrix/app/service/internal/processconfig"
	"github.com/xiak/matrix/app/service/internal/processhttp"
)

const (
	listenAddressEnvironment        = "MATRIX_PLATFORM_LISTEN_ADDRESS"
	iamEndpointEnvironment          = "MATRIX_PLATFORM_IAM_ENDPOINT"
	iamCredentialFileEnvironment    = "MATRIX_PLATFORM_IAM_CREDENTIAL_FILE"
	installationIDEnvironment       = "MATRIX_PLATFORM_INSTALLATION_ID"
	releaseIDEnvironment            = "MATRIX_PLATFORM_RELEASE_ID"
	releaseManifestFileEnvironment  = "MATRIX_PLATFORM_RELEASE_MANIFEST_FILE"
	releaseSignatureFileEnvironment = "MATRIX_PLATFORM_RELEASE_SIGNATURE_FILE"
	releaseTrustFileEnvironment     = "MATRIX_PLATFORM_RELEASE_TRUST_FILE"
	paasEndpointEnvironment         = "MATRIX_PLATFORM_PAAS_ENDPOINT"
	devopsEndpointEnvironment       = "MATRIX_PLATFORM_DEVOPS_ENDPOINT"

	maximumManifestBytes   int64 = 1024 * 1024
	maximumSignatureBytes  int64 = 64
	maximumTrustBytes      int64 = 16 * 1024
	maximumCredentialBytes int64 = 16 * 1024
)

type configuration struct {
	listenAddress        string
	iamEndpoint          string
	iamCredentialFile    string
	installationID       string
	releaseID            string
	releaseManifestFile  string
	releaseSignatureFile string
	releaseTrustFile     string
	paasEndpoint         string
	devopsEndpoint       string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Getenv); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix platform process failed")
		os.Exit(1)
	}
}

func run(ctx context.Context, lookup func(string) string) error {
	config, err := loadConfiguration(lookup)
	if err != nil {
		return err
	}
	handler, err := buildHandler(config)
	if err != nil {
		return err
	}
	return processhttp.Serve(ctx, config.listenAddress, handler)
}

func loadConfiguration(lookup func(string) string) (configuration, error) {
	if lookup == nil {
		return configuration{}, errors.New("platform configuration source is unavailable")
	}
	config := configuration{
		listenAddress:        lookup(listenAddressEnvironment),
		iamEndpoint:          lookup(iamEndpointEnvironment),
		iamCredentialFile:    lookup(iamCredentialFileEnvironment),
		installationID:       lookup(installationIDEnvironment),
		releaseID:            lookup(releaseIDEnvironment),
		releaseManifestFile:  lookup(releaseManifestFileEnvironment),
		releaseSignatureFile: lookup(releaseSignatureFileEnvironment),
		releaseTrustFile:     lookup(releaseTrustFileEnvironment),
		paasEndpoint:         lookup(paasEndpointEnvironment),
		devopsEndpoint:       lookup(devopsEndpointEnvironment),
	}
	if config.listenAddress == "" || config.iamEndpoint == "" ||
		config.iamCredentialFile == "" || config.releaseID == "" ||
		config.releaseManifestFile == "" || config.releaseSignatureFile == "" ||
		config.releaseTrustFile == "" || config.paasEndpoint == "" ||
		lifecycle.ValidateInstallationID(config.installationID) != nil {
		return configuration{}, errors.New("platform process configuration is incomplete or invalid")
	}
	for _, target := range []string{
		config.iamCredentialFile,
		config.releaseManifestFile,
		config.releaseSignatureFile,
		config.releaseTrustFile,
	} {
		if !filepath.IsAbs(target) || filepath.Clean(target) != target {
			return configuration{}, errors.New("platform process file configuration is invalid")
		}
	}
	return config, nil
}

func buildHandler(config configuration) (http.Handler, error) {
	manifestBytes, err := processconfig.ReadFile(
		config.releaseManifestFile,
		maximumManifestBytes,
		false,
	)
	if err != nil {
		return nil, errors.New("platform release manifest is unavailable")
	}
	signature, err := processconfig.ReadFile(
		config.releaseSignatureFile,
		maximumSignatureBytes,
		false,
	)
	if err != nil {
		return nil, errors.New("platform release signature is unavailable")
	}
	trustBytes, err := processconfig.ReadFile(
		config.releaseTrustFile,
		maximumTrustBytes,
		false,
	)
	if err != nil {
		return nil, errors.New("platform release trust root is unavailable")
	}
	manifest, err := release.Verify(manifestBytes, signature, trustBytes)
	if err != nil || manifest.Release.ID != config.releaseID {
		return nil, errors.New("platform release identity cannot be authenticated")
	}
	if manifest.IncludesProduct(release.ProductDevOps) != (config.devopsEndpoint != "") {
		return nil, errors.New("platform product readiness configuration differs from release")
	}

	credentialText, err := processconfig.ReadText(
		config.iamCredentialFile,
		maximumCredentialBytes,
		true,
	)
	if err != nil {
		return nil, errors.New("platform IAM credential is unavailable")
	}
	credential, err := iamv1.NewSecret(credentialText)
	credentialText = ""
	if err != nil {
		return nil, errors.New("platform IAM credential is invalid")
	}
	authorizer, err := iamhttp.NewClient(iamhttp.Config{
		Endpoint: config.iamEndpoint, ServiceCredential: credential,
	})
	if err != nil {
		return nil, err
	}
	observer, err := readinesshttp.NewObserver(readinesshttp.Config{
		PaaSEndpoint: config.paasEndpoint, DevOpsEndpoint: config.devopsEndpoint,
	})
	if err != nil {
		return nil, err
	}
	workflow, err := productdiscovery.NewService(
		manifest,
		authorizer,
		observer,
		productdiscovery.Config{InstallationID: config.installationID},
	)
	if err != nil {
		return nil, err
	}
	return producthttp.NewHandler(workflow, producthttp.Config{})
}
