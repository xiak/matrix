package managedserviceonboarding

import (
	_ "embed"
	"encoding/json"
	"errors"
	"regexp"
)

const ElasticVersion = "8.19.23"

//go:embed artifacts.json
var artifactCatalog []byte

// ArtifactReferences returns the exact local test preparation inventory.
// Loading it never pulls an image or changes the platform release inventory.
func ArtifactReferences() (map[string]string, error) {
	var artifacts map[string]string
	if json.Unmarshal(artifactCatalog, &artifacts) != nil || len(artifacts) != 4 {
		return nil, errors.New("onboarding artifact inventory is invalid")
	}
	for product, repository := range map[string]string{
		"elasticsearch": "docker.elastic.co/elasticsearch/elasticsearch",
		"logstash":      "docker.elastic.co/logstash/logstash",
		"kibana":        "docker.elastic.co/kibana/kibana",
		"redis":         "redis",
	} {
		pattern := regexp.MustCompile("^" + regexp.QuoteMeta(repository) + "@sha256:[0-9a-f]{64}$")
		if !pattern.MatchString(artifacts[product]) {
			return nil, errors.New("onboarding artifact must use its exact trusted repository and digest")
		}
	}
	return artifacts, nil
}
