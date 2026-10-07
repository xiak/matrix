//go:build matrix_authority_future_profile_fixture

package iamv1

// authorizationProfilesForBuild produces the independently built future
// declaration used by the authority-process acceptance gate. It is excluded
// from every ordinary and release build; the gate opts in with an explicit
// build tag and then exercises the normal migration and runtime paths.
func authorizationProfilesForBuild(profiles []AuthorizationProfile) []AuthorizationProfile {
	result := make([]AuthorizationProfile, len(profiles))
	for index, profile := range profiles {
		result[index] = cloneAuthorizationProfile(profile)
	}

	foundProfile := false
	for profileIndex := range result {
		if result[profileIndex].Product != ProductPaaS {
			continue
		}
		if foundProfile {
			panic("future fixture found duplicate PaaS profiles")
		}
		foundProfile = true

		profile := result[profileIndex]
		var added AuthorizationProfileAction
		foundAction := false
		for actionIndex := range profile.Actions {
			if profile.Actions[actionIndex].Action != ActionPaaSApplicationRead {
				continue
			}
			if foundAction {
				panic("future fixture found duplicate PaaS Application read actions")
			}
			foundAction = true
			added = profile.Actions[actionIndex]
			conditions := make([]AuthorizationProfileCondition, 0, len(added.Conditions))
			for _, condition := range added.Conditions {
				if condition.Key != ConditionIAMPrincipalID {
					conditions = append(conditions, condition)
				}
			}
			profile.Actions[actionIndex].Conditions = conditions
		}
		if !foundAction {
			panic("future fixture requires the PaaS Application read action")
		}

		profile.Revision++
		added.Action = Action("paas.application.inspect")
		profile.Actions = append(profile.Actions, added)
		result[profileIndex] = profile
	}
	if !foundProfile {
		panic("future fixture requires the PaaS authorization profile")
	}
	return result
}
