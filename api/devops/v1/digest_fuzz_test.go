package devopsv1

import "testing"

func FuzzPipelineDraftDigestIsFramed(f *testing.F) {
	f.Add("binding-a", "binding-b")
	f.Add("a", "ab")
	f.Fuzz(func(t *testing.T, first, second string) {
		left := validDraftSpec()
		right := validDraftSpec()
		left.RepositoryBindingID = ResourceID(first)
		right.RepositoryBindingID = ResourceID(second)
		leftDigest := PipelineDraftSpecDigest(left)
		rightDigest := PipelineDraftSpecDigest(right)
		if first == second && leftDigest != rightDigest {
			t.Fatal("equal inputs produced different digests")
		}
		if first != second && leftDigest == rightDigest {
			t.Fatal("distinct framed repository identities produced the same digest")
		}
	})
}

func FuzzRepositoryBindingDigestIsFramed(f *testing.F) {
	f.Add("platform/api", "platform/worker")
	f.Add("a/b", "a/bb")
	f.Fuzz(func(t *testing.T, first, second string) {
		left := validRepositoryBindingSpec()
		right := validRepositoryBindingSpec()
		left.RepositoryPath = first
		right.RepositoryPath = second
		leftDigest := RepositoryBindingSpecDigest(left)
		rightDigest := RepositoryBindingSpecDigest(right)
		if first == second && leftDigest != rightDigest {
			t.Fatal("equal inputs produced different repository binding digests")
		}
		if first != second && leftDigest == rightDigest {
			t.Fatal("distinct framed repository identities produced the same digest")
		}
	})
}
