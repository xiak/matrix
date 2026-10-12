//go:build windows

package localcontainer

// The local providers are rejected by their readiness checks on Windows.
// Unit tests can still compile their documents without inventing a POSIX group.
func credentialFileGroupID(string) (uint32, bool, error) {
	return 0, false, nil
}
