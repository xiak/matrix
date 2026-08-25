package localmachine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
)

const machineIdentityVersion = "matrix.localmachine.identity/v1"

func DeriveMachineFingerprint(facts HostFacts) (string, error) {
	if err := validateHostFacts(facts); err != nil {
		return "", err
	}
	digest := sha256.New()
	writeMachineIdentityPart(digest, machineIdentityVersion)
	writeMachineIdentityPart(digest, facts.MachineID)
	writeMachineIdentityPart(digest, facts.OperatingSystem)
	writeMachineIdentityPart(digest, facts.Architecture)
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

func writeMachineIdentityPart(target hash.Hash, value string) {
	_, _ = fmt.Fprintf(target, "%d:", len(value))
	_, _ = target.Write([]byte(value))
}
