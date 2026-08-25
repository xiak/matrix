package release

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	maximumManifestBytes = 1024 * 1024
	maximumTrustBytes    = 16 * 1024
	minimumFreeBytes     = 1024 * 1024 * 1024
	maximumFreeBytes     = uint64(1) << 50
	maximumPayloadBytes  = uint64(1) << 40

	mediaExecutable    = "application/vnd.matrix.executable"
	mediaDockerArchive = "application/vnd.docker.image.archive"
	mediaMarkdown      = "text/markdown"
	mediaPlainText     = "text/plain"
)

var (
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	versionPattern     = regexp.MustCompile(`^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z](?:[0-9A-Za-z.-]{0,62}[0-9A-Za-z])?)?$`)
	commitPattern      = regexp.MustCompile(`^[0-9a-f]{40}$`)
	shortCommitPattern = regexp.MustCompile(`^[0-9a-f]{12}$`)
	safeTokenPattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$`)
	keyIDPattern       = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._@+-]{0,126}[A-Za-z0-9])?$`)
	pathPartPattern    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$`)
)

func EncodeCanonical(manifest Manifest) ([]byte, error) {
	if err := ValidateManifest(manifest); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, errors.New("encode release manifest failed")
	}
	return encoded, nil
}

func DecodeCanonical(content []byte) (Manifest, error) {
	if len(content) == 0 || len(content) > maximumManifestBytes {
		return Manifest{}, errors.New("release manifest size is invalid")
	}
	var manifest Manifest
	if err := decodeStrict(content, &manifest); err != nil {
		return Manifest{}, errors.New("release manifest is invalid")
	}
	encoded, err := EncodeCanonical(manifest)
	if err != nil || !bytes.Equal(encoded, content) {
		return Manifest{}, errors.New("release manifest is not canonical")
	}
	return manifest, nil
}

func ValidateManifest(manifest Manifest) error {
	var problems []error
	if manifest.APIVersion != ManifestAPIVersion || manifest.Kind != ManifestKind {
		problems = append(problems, errors.New("release type is unsupported"))
	}
	problems = append(problems,
		validateReleaseIdentity(manifest.Release),
		validateSigner(manifest.Signer),
		validateHost(manifest.Host),
		validateDatabase(manifest.Database),
		validateDigest("topologyDigest", manifest.TopologyDigest),
		validateFiles(manifest.Files),
		validateImages(manifest.Images, manifest.Files),
	)
	if manifest.MinimumFreeBytes < minimumFreeBytes || manifest.MinimumFreeBytes > maximumFreeBytes {
		problems = append(problems, errors.New("minimum free space is outside the supported range"))
	}
	return errors.Join(problems...)
}

func validateReleaseIdentity(value ReleaseIdentity) error {
	var problems []error
	if !versionPattern.MatchString(value.Version) || !commitPattern.MatchString(value.SourceCommit) {
		problems = append(problems, errors.New("release version or source commit is invalid"))
	} else if value.ID != "matrix-"+value.Version+"-"+value.SourceCommit[:12] {
		problems = append(problems, errors.New("release identity does not match version and source commit"))
	}
	if !safeTokenPattern.MatchString(value.BuildID) {
		problems = append(problems, errors.New("release build identity is invalid"))
	}
	if !canonicalTime(value.CreatedAt) {
		problems = append(problems, errors.New("release creation time is invalid"))
	}
	hasPreviousID := value.PreviousID != ""
	hasPreviousVersion := value.PreviousVersion != ""
	if hasPreviousID != hasPreviousVersion {
		problems = append(problems, errors.New("previous release identity is incomplete"))
	} else if hasPreviousID {
		prefix := "matrix-" + value.PreviousVersion + "-"
		shortCommit := strings.TrimPrefix(value.PreviousID, prefix)
		if !versionPattern.MatchString(value.PreviousVersion) || value.PreviousID == value.ID ||
			value.PreviousVersion == value.Version || !strings.HasPrefix(value.PreviousID, prefix) ||
			!shortCommitPattern.MatchString(shortCommit) {
			problems = append(problems, errors.New("previous release constraint is invalid"))
		}
	}
	return errors.Join(problems...)
}

func validateSigner(value Signer) error {
	if !keyIDPattern.MatchString(value.KeyID) || value.Algorithm != SignatureAlgorithm {
		return errors.New("release signer is invalid")
	}
	return nil
}

func validateHost(value HostProfile) error {
	if value.OS != "linux" || value.Architecture != "amd64" ||
		!versionPattern.MatchString("v"+value.MinimumDocker) ||
		!versionPattern.MatchString("v"+value.MinimumCompose) ||
		value.CommandContract != "v1" {
		return errors.New("release host profile is invalid")
	}
	return nil
}

func validateDatabase(value DatabaseProfile) error {
	if value.SchemaVersion == 0 || value.SchemaVersion > 9007199254740991 ||
		value.Compatibility != "expand-contract-n-minus-one" {
		return errors.New("release database profile is invalid")
	}
	return nil
}

func validateFiles(files []File) error {
	if len(files) < 7 || len(files) > 128 {
		return errors.New("release payload inventory size is invalid")
	}
	seen := make(map[string]struct{}, len(files))
	previous := ""
	foundExecutable := false
	for _, file := range files {
		if err := validateRelativePath(file.Path); err != nil {
			return err
		}
		folded := strings.ToLower(file.Path)
		if _, duplicate := seen[folded]; duplicate || previous >= file.Path {
			return errors.New("release payload paths are duplicated or not sorted")
		}
		seen[folded] = struct{}{}
		previous = file.Path
		if file.Size == 0 || file.Size > maximumPayloadBytes || validateDigest("file digest", file.SHA256) != nil {
			return errors.New("release payload metadata is invalid")
		}
		switch {
		case file.Path == "bin/mx":
			if file.MediaType != mediaExecutable || !file.Executable {
				return errors.New("release mx payload is invalid")
			}
			foundExecutable = true
		case strings.HasPrefix(file.Path, "images/") && strings.HasSuffix(file.Path, ".tar"):
			if file.MediaType != mediaDockerArchive || file.Executable {
				return errors.New("release image archive payload is invalid")
			}
		case strings.HasPrefix(file.Path, "docs/") && strings.HasSuffix(file.Path, ".md"):
			if file.MediaType != mediaMarkdown || file.Executable || file.Size > maximumManifestBytes {
				return errors.New("release documentation payload is invalid")
			}
		case strings.HasPrefix(file.Path, "licenses/") && strings.HasSuffix(file.Path, ".txt"):
			if file.MediaType != mediaPlainText || file.Executable || file.Size > maximumManifestBytes {
				return errors.New("release license payload is invalid")
			}
		default:
			return errors.New("release payload kind is unsupported")
		}
	}
	if !foundExecutable {
		return errors.New("release mx payload is missing")
	}
	return nil
}

func validateImages(images []Image, files []File) error {
	required := RequiredImages()
	if len(images) != len(required) {
		return errors.New("release image inventory is incomplete")
	}
	fileByPath := make(map[string]File, len(files))
	for _, file := range files {
		fileByPath[file.Path] = file
	}
	for index, image := range images {
		requirement := required[index]
		if image.Component != requirement.Component || image.Purpose != requirement.Purpose ||
			image.ArchivePath != "images/"+requirement.Component+".tar" ||
			!digestPattern.MatchString(image.ImageID) ||
			!digestPattern.MatchString(image.SourceDigest) ||
			image.OS != "linux" || image.Architecture != "amd64" ||
			image.HealthContract != requirement.HealthContract {
			return errors.New("release image declaration is invalid")
		}
		file, found := fileByPath[image.ArchivePath]
		if !found || file.MediaType != mediaDockerArchive {
			return errors.New("release image archive is absent from payload inventory")
		}
	}
	return nil
}

func validateRelativePath(value string) error {
	if value == "" || len(value) > 512 || value == "release.json" || value == "release.sig" ||
		strings.ContainsAny(value, "\\:\x00\r\n") || strings.HasPrefix(value, "/") ||
		path.Clean(value) != value {
		return errors.New("release payload path is unsafe")
	}
	parts := strings.Split(value, "/")
	if len(parts) < 2 || slices.Contains(parts, "") {
		return errors.New("release payload path is unsafe")
	}
	for _, part := range parts {
		if !pathPartPattern.MatchString(part) {
			return errors.New("release payload path is unsafe")
		}
	}
	return nil
}

func validateDigest(label, value string) error {
	if !digestPattern.MatchString(value) {
		return fmt.Errorf("%s is invalid", label)
	}
	return nil
}

func canonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value == value.Round(0) &&
		value.Nanosecond()%1000 == 0
}

func decodeStrict(content []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON has trailing content")
	}
	return nil
}
