package releasebuild

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func writeImageContext(
	root string,
	recipe imageRecipe,
	config Config,
	binaries map[string]string,
) error {
	if err := os.MkdirAll(root, 0o700); err != nil || os.Chmod(root, 0o700) != nil {
		return errors.New("create release image context failed")
	}
	for _, name := range recipe.binaries {
		source, found := binaries[name]
		if !found {
			return errors.New("release image executable is missing")
		}
		if err := copyRegularFile(source, filepath.Join(root, name), 0o600); err != nil {
			return err
		}
	}
	dockerfile, err := encodeDockerfile(recipe, config)
	if err != nil {
		return err
	}
	return writeExclusive(filepath.Join(root, "Dockerfile"), dockerfile, 0o600)
}

func encodeDockerfile(recipe imageRecipe, config Config) ([]byte, error) {
	if recipe.component == "" || recipe.baseReference == "" || len(recipe.binaries) == 0 {
		return nil, errors.New("release image recipe is invalid")
	}
	var document strings.Builder
	document.WriteString("FROM ")
	document.WriteString(recipe.baseReference)
	document.WriteByte('\n')
	document.WriteString("LABEL com.xiak.matrix.release-build=\"true\" ")
	document.WriteString("com.xiak.matrix.component=\"")
	document.WriteString(recipe.component)
	document.WriteString("\" com.xiak.matrix.source-commit=\"")
	document.WriteString(config.SourceCommit)
	document.WriteString("\" com.xiak.matrix.build-id=\"")
	document.WriteString(config.BuildID)
	document.WriteString("\"\n")
	for _, name := range recipe.binaries {
		document.WriteString("COPY --chmod=0555 ")
		document.WriteString(name)
		document.WriteString(" /matrix/bin/")
		document.WriteString(name)
		document.WriteByte('\n')
	}
	if recipe.entrypoint != "" {
		encoded, err := json.Marshal([]string{recipe.entrypoint})
		if err != nil {
			return nil, errors.New("encode release image entrypoint failed")
		}
		document.WriteString("ENTRYPOINT ")
		document.Write(encoded)
		document.WriteByte('\n')
	}
	return []byte(document.String()), nil
}
