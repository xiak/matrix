//go:build !matrix_authority_future_profile_fixture

package iamv1

// authorizationProfilesForBuild is the production catalog boundary. The
// tagged acceptance fixture replaces only this transform so it can build a
// real future executable without parsing or rewriting this package's source.
func authorizationProfilesForBuild(profiles []AuthorizationProfile) []AuthorizationProfile {
	return profiles
}
