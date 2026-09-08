package gitea

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	git "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/sourcearchive"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/runlifecycle"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/usecase/sourceacquisition"
	"github.com/xiak/matrix/app/service/devops/sourcecredential"
)

const (
	gitDialTimeout            = 5 * time.Second
	gitResponseHeaderTimeout  = 10 * time.Second
	maximumAdvertisementBytes = int64(1024 * 1024)
	maximumUploadPackBytes    = sourcearchive.MaximumExpandedBytes + sourcearchive.MaximumArchiveBytes
	maximumTreeDepth          = 128
	gitAuthenticationUsername = "matrix-source-fetch"
	localBaseReference        = plumbing.ReferenceName("refs/matrix/base")
	localHeadReference        = plumbing.ReferenceName("refs/matrix/head")
)

var httpsProtocolMutex sync.Mutex

type Fetcher struct {
	credentials CredentialResolver
	client      *http.Client
}

var _ sourceacquisition.SourceFetcher = (*Fetcher)(nil)

func NewFetcher(credentials CredentialResolver) (*Fetcher, error) {
	if credentials == nil {
		return nil, errors.New("Gitea source fetch credential resolver is required")
	}
	dialer := &net.Dialer{Timeout: gitDialTimeout, KeepAlive: -1}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		ForceAttemptHTTP2:      true,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		TLSHandshakeTimeout:    gitDialTimeout,
		ResponseHeaderTimeout:  gitResponseHeaderTimeout,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: maximumAdvertisementBytes,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return newFetcher(credentials, &http.Client{
		Transport: transport,
		Timeout:   sourceacquisition.AcquisitionDeadline,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("provider redirects are not permitted")
		},
	})
}

func newFetcher(credentials CredentialResolver, httpClient *http.Client) (*Fetcher, error) {
	if credentials == nil || httpClient == nil || httpClient.Transport == nil ||
		httpClient.Timeout != sourceacquisition.AcquisitionDeadline || httpClient.CheckRedirect == nil {
		return nil, errors.New("Gitea source fetcher configuration is invalid")
	}
	return &Fetcher{credentials: credentials, client: httpClient}, nil
}

func (fetcher *Fetcher) Fetch(
	ctx context.Context,
	command sourceacquisition.Command,
	destination io.Writer,
) (sourceacquisition.ArchiveContent, error) {
	if fetcher == nil || fetcher.credentials == nil || fetcher.client == nil ||
		ctx == nil || destination == nil || sourceacquisition.ValidateCommand(command) != nil ||
		command.Connection.Spec.AdapterID != AdapterID ||
		command.Lease.Mode != runlifecycle.ClaimExecute {
		return sourceacquisition.ArchiveContent{}, sourceacquisition.ErrSourceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return sourceacquisition.ArchiveContent{}, err
	}
	headCommit := command.Lease.Run.Input.Change.HeadCommit
	baseCommit := command.Lease.Run.Input.Change.TrustedBaseCommit
	if !validSHA1(headCommit) || !validSHA1(baseCommit) {
		return sourceacquisition.ArchiveContent{}, sourceacquisition.ErrSourceUnavailable
	}
	repositoryURL, repositoryPath, err := fetchRepositoryURL(
		command.Connection.Spec.EndpointOrigin,
		command.BindingRevision.Spec.RepositoryPath,
	)
	if err != nil {
		return sourceacquisition.ArchiveContent{}, sourceacquisition.ErrSourceUnavailable
	}

	material, err := fetcher.credentials.Resolve(
		ctx,
		command.Connection.Metadata.Scope,
		command.Connection.Spec.FetchCredentialRef,
	)
	if err != nil {
		return sourceacquisition.ArchiveContent{}, fetchFailure(ctx, err)
	}
	defer material.Clear()
	credential, err := sourcecredential.NewMaterial(
		sourcecredential.PurposeFetch, material.Current, nil,
	)
	if err != nil {
		return sourceacquisition.ArchiveContent{}, sourceacquisition.ErrSourceUnavailable
	}
	defer credential.Clear()
	authentication := &githttp.BasicAuth{
		Username: gitAuthenticationUsername,
		Password: string(credential.Current),
	}
	defer func() { authentication.Password = "" }()

	storage := memory.NewStorage()
	repository, err := git.Init(storage, nil)
	if err != nil {
		return sourceacquisition.ArchiveContent{}, sourceacquisition.ErrSourceUnavailable
	}
	remote, err := repository.CreateRemote(&gitconfig.RemoteConfig{
		Name: "origin", URLs: []string{repositoryURL},
	})
	if err != nil {
		return sourceacquisition.ArchiveContent{}, sourceacquisition.ErrSourceUnavailable
	}
	baseSource := plumbing.ReferenceName(
		"refs/heads/" + command.BindingRevision.Spec.TrustedDefaultBranch,
	)
	headSource := plumbing.ReferenceName(
		"refs/pull/" + strconv.FormatUint(command.Lease.Run.Input.Change.Number, 10) + "/head",
	)
	if baseSource.Validate() != nil || headSource.Validate() != nil {
		return sourceacquisition.ArchiveContent{}, sourceacquisition.ErrSourceUnavailable
	}
	refspecs := []gitconfig.RefSpec{
		gitconfig.RefSpec("+" + baseSource.String() + ":" + localBaseReference.String()),
		gitconfig.RefSpec("+" + headSource.String() + ":" + localHeadReference.String()),
	}
	for _, refspec := range refspecs {
		if refspec.Validate() != nil {
			return sourceacquisition.ArchiveContent{}, sourceacquisition.ErrSourceUnavailable
		}
	}

	closedClient := *fetcher.client
	closedClient.Transport = &closedGitTransport{
		base: fetcher.client.Transport, endpointOrigin: command.Connection.Spec.EndpointOrigin,
		repositoryPath: repositoryPath,
	}
	err = fetchWithHTTPSClient(&closedClient, func() error {
		return remote.FetchContext(ctx, &git.FetchOptions{
			RefSpecs: refspecs, Depth: 1, Auth: authentication,
			Tags: git.NoTags, Force: true,
		})
	})
	closedClient.CloseIdleConnections()
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return sourceacquisition.ArchiveContent{}, fetchFailure(ctx, err)
	}
	expectedHead := plumbing.NewHash(headCommit)
	expectedBase := plumbing.NewHash(baseCommit)
	if !referenceMatches(repository, localHeadReference, expectedHead) ||
		!referenceMatches(repository, localBaseReference, expectedBase) {
		return sourceacquisition.ArchiveContent{}, sourceacquisition.ErrCommitMismatch
	}
	head, err := repository.CommitObject(expectedHead)
	if err != nil || head.Hash != expectedHead {
		return sourceacquisition.ArchiveContent{}, sourceacquisition.ErrSourceUnavailable
	}
	base, err := repository.CommitObject(expectedBase)
	if err != nil || base.Hash != expectedBase {
		return sourceacquisition.ArchiveContent{}, sourceacquisition.ErrSourceUnavailable
	}
	return archiveCommit(ctx, repository, head, destination)
}

func fetchWithHTTPSClient(httpClient *http.Client, fetch func() error) error {
	httpsProtocolMutex.Lock()
	defer httpsProtocolMutex.Unlock()
	previous, found := client.Protocols["https"]
	client.InstallProtocol("https", githttp.NewClientWithOptions(httpClient, &githttp.ClientOptions{
		CacheMaxEntries: 1, RedirectPolicy: githttp.NoFollowRedirects,
	}))
	defer func() {
		if found {
			client.InstallProtocol("https", previous)
		} else {
			delete(client.Protocols, "https")
		}
	}()
	return fetch()
}

func archiveCommit(
	ctx context.Context,
	repository *git.Repository,
	commit *object.Commit,
	destination io.Writer,
) (sourceacquisition.ArchiveContent, error) {
	if ctx == nil || repository == nil || commit == nil || destination == nil {
		return sourceacquisition.ArchiveContent{}, sourceacquisition.ErrSourceUnavailable
	}
	tree, err := commit.Tree()
	if err != nil {
		return sourceacquisition.ArchiveContent{}, fetchFailure(ctx, err)
	}
	state := treeWalkState{}
	if err := collectSourceFiles(ctx, repository, tree, "", 0, &state); err != nil {
		return sourceacquisition.ArchiveContent{}, fetchFailure(ctx, err)
	}
	content, err := sourcearchive.Write(ctx, destination, state.files)
	if err != nil {
		return sourceacquisition.ArchiveContent{}, fetchFailure(ctx, err)
	}
	return content, nil
}

type treeWalkState struct {
	entries       uint64
	expandedBytes int64
	files         []sourcearchive.File
}

func collectSourceFiles(
	ctx context.Context,
	repository *git.Repository,
	tree *object.Tree,
	prefix string,
	depth int,
	state *treeWalkState,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if depth > maximumTreeDepth || state == nil || tree == nil {
		return sourcearchive.ErrInvalid
	}
	entries := append([]object.TreeEntry(nil), tree.Entries...)
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name < entries[right].Name })
	for index, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if index > 0 && entries[index-1].Name == entry.Name ||
			entry.Name == "" || strings.Contains(entry.Name, "/") ||
			state.entries >= sourcearchive.MaximumPathCount {
			return sourcearchive.ErrInvalid
		}
		state.entries++
		filePath := entry.Name
		if prefix != "" {
			filePath = prefix + "/" + entry.Name
		}
		if sourcearchive.ValidatePath(filePath) != nil {
			return sourcearchive.ErrInvalid
		}
		switch entry.Mode {
		case filemode.Dir:
			child, err := repository.TreeObject(entry.Hash)
			if err != nil {
				return err
			}
			if err := collectSourceFiles(ctx, repository, child, filePath, depth+1, state); err != nil {
				return err
			}
		case filemode.Regular, filemode.Executable:
			blob, err := repository.BlobObject(entry.Hash)
			if err != nil || blob.Size < 0 ||
				blob.Size > sourcearchive.MaximumExpandedBytes-state.expandedBytes {
				return sourcearchive.ErrInvalid
			}
			state.expandedBytes += blob.Size
			fileBlob := blob
			state.files = append(state.files, sourcearchive.File{
				Path: filePath, Executable: entry.Mode == filemode.Executable, Size: blob.Size,
				Open: fileBlob.Reader,
			})
		default:
			return sourcearchive.ErrInvalid
		}
	}
	return nil
}

func referenceMatches(
	repository *git.Repository,
	name plumbing.ReferenceName,
	want plumbing.Hash,
) bool {
	reference, err := repository.Reference(name, true)
	return err == nil && reference.Name() == name && reference.Hash() == want
}

func validSHA1(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func fetchRepositoryURL(endpointOrigin, repositoryPath string) (string, string, error) {
	segments := strings.Split(repositoryPath, "/")
	endpoint, err := url.Parse(endpointOrigin)
	if err != nil || len(segments) != 2 || endpoint.Scheme != "https" || endpoint.Host == "" ||
		endpoint.User != nil || endpoint.Path != "" || endpoint.RawPath != "" ||
		endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" {
		return "", "", errors.New("Gitea fetch origin is invalid")
	}
	repositoryURLPath := "/" + url.PathEscape(segments[0]) + "/" + url.PathEscape(segments[1]) + ".git"
	endpoint.Path = repositoryURLPath
	return endpoint.String(), repositoryURLPath, nil
}

func fetchFailure(ctx context.Context, cause error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(cause, sourceacquisition.ErrCommitMismatch) {
		return sourceacquisition.ErrCommitMismatch
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return sourceacquisition.ErrSourceUnavailable
}

type closedGitTransport struct {
	base           http.RoundTripper
	endpointOrigin string
	repositoryPath string
}

func (transport *closedGitTransport) CloseIdleConnections() {
	if closer, ok := transport.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (transport *closedGitTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if transport == nil || transport.base == nil || request == nil || request.URL == nil {
		return nil, sourceacquisition.ErrSourceUnavailable
	}
	origin := request.URL.Scheme + "://" + request.URL.Host
	infoRefs := transport.repositoryPath + "/info/refs"
	uploadPack := transport.repositoryPath + "/git-upload-pack"
	maximumBytes := maximumUploadPackBytes
	validRequest := request.URL.Scheme == "https" && origin == transport.endpointOrigin &&
		request.URL.User == nil && request.URL.Fragment == "" && request.URL.Opaque == "" &&
		request.URL.RawPath == "" && !request.URL.ForceQuery
	switch {
	case request.Method == http.MethodGet && request.URL.Path == infoRefs &&
		request.URL.RawQuery == "service=git-upload-pack":
		maximumBytes = maximumAdvertisementBytes
	case request.Method == http.MethodPost && request.URL.Path == uploadPack && request.URL.RawQuery == "":
	default:
		validRequest = false
	}
	if !validRequest {
		return nil, sourceacquisition.ErrSourceUnavailable
	}
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return response, err
	}
	if response == nil || response.Body == nil ||
		(response.ContentLength > maximumBytes && response.ContentLength >= 0) {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, sourceacquisition.ErrSourceUnavailable
	}
	response.Body = &boundedReadCloser{source: response.Body, remaining: maximumBytes}
	return response, nil
}

type boundedReadCloser struct {
	source    io.ReadCloser
	remaining int64
	exhausted bool
}

func (reader *boundedReadCloser) Read(buffer []byte) (int, error) {
	if reader.exhausted {
		return 0, sourceacquisition.ErrSourceUnavailable
	}
	if int64(len(buffer)) > reader.remaining+1 {
		buffer = buffer[:reader.remaining+1]
	}
	written, err := reader.source.Read(buffer)
	reader.remaining -= int64(written)
	if reader.remaining < 0 {
		reader.exhausted = true
		return 0, sourceacquisition.ErrSourceUnavailable
	}
	return written, err
}

func (reader *boundedReadCloser) Close() error {
	return reader.source.Close()
}
