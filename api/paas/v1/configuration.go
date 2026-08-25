package paasv1

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"slices"
)

// ConfigurationValuesDigest returns a deterministic digest without relying
// on map iteration or ambiguous delimiter escaping.
func ConfigurationValuesDigest(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	digest := sha256.New()
	writeDigestLength(digest, uint64(len(keys)))
	for _, key := range keys {
		writeDigestBytes(digest, []byte(key))
		writeDigestBytes(digest, []byte(values[key]))
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func writeDigestBytes(target hash.Hash, value []byte) {
	writeDigestLength(target, uint64(len(value)))
	_, _ = target.Write(value)
}

func writeDigestLength(target hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = target.Write(encoded[:])
}
