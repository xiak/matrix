// prepare is an explicit network-enabled fixture preparation step. The
// providers and real acceptance gate themselves never download artifacts.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	onboarding "github.com/xiak/matrix/test/managedserviceonboarding"
)

func main() {
	pull := flag.Bool("pull", false, "download the exact pinned fixture images before checking local availability")
	flag.Parse()
	if err := run(*pull); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(pull bool) error {
	artifacts, err := onboarding.ArtifactReferences()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	for _, product := range slices.Sorted(maps.Keys(artifacts)) {
		reference := artifacts[product]
		if pull {
			command := exec.CommandContext(ctx, "docker", "pull", "--platform", "linux/amd64", reference)
			command.Stdout, command.Stderr = os.Stdout, os.Stderr
			if command.Run() != nil {
				return fmt.Errorf("%s fixture download failed", product)
			}
		}
		value, err := exec.CommandContext(ctx, "docker", "image", "inspect", "--format", "{{.Id}}|{{.Architecture}}|{{.Os}}", reference).Output()
		if err != nil {
			return fmt.Errorf("%s fixture is absent; explicitly prepare it with -pull or import the exact offline image", product)
		}
		fields := strings.Split(strings.TrimSpace(string(value)), "|")
		if len(fields) != 3 || !strings.HasPrefix(fields[0], "sha256:") || fields[1] != "amd64" || fields[2] != "linux" {
			return errors.New("fixture image does not satisfy the linux/amd64 contract")
		}
		if err := json.NewEncoder(os.Stdout).Encode(map[string]string{"product": product, "reference": reference, "imageId": fields[0]}); err != nil {
			return err
		}
	}
	return nil
}
