package devopsv1

const (
	Go126OfflineToolchainImageDigest = "sha256:07558d5472e9acb5fc5656b485e963602e925e00111b8ad676a804306e711ba3"

	FixedStepTimeoutSeconds uint32 = 600
	FixedRunTimeoutSeconds  uint32 = 1_200
	FixedCPUMillis          int64  = 2_000
	FixedMemoryBytes        int64  = 2 * 1024 * 1024 * 1024
	FixedWritableBytes      int64  = 2 * 1024 * 1024 * 1024
	FixedProcessLimit       uint32 = 256
	FixedMaxLogBytes        int64  = 8 * 1024 * 1024
	FixedMaxLogLineBytes    int64  = 16 * 1024
	FixedMaxLogChunkBytes   int64  = 64 * 1024
	FixedLogPageChunkCount         = 4
	FixedMaxLogPageBytes    int64  = 640 * 1024

	MaximumSourceArchiveBytes  int64  = 64 * 1024 * 1024
	MaximumSourceExpandedBytes int64  = 512 * 1024 * 1024
	MaximumSourcePathCount     uint64 = 20_000
)

// FixedVerificationSteps returns a copy so callers cannot mutate the trusted
// catalog shared by another activation.
func FixedVerificationSteps() []VerificationStep {
	return []VerificationStep{
		{Ordinal: 1, Kind: VerificationStepGoTest},
		{Ordinal: 2, Kind: VerificationStepGoVet},
	}
}

func FixedVerificationLimits() VerificationLimits {
	return VerificationLimits{
		StepTimeoutSeconds: FixedStepTimeoutSeconds,
		RunTimeoutSeconds:  FixedRunTimeoutSeconds,
		CPUMillis:          FixedCPUMillis,
		MemoryBytes:        FixedMemoryBytes,
		WritableBytes:      FixedWritableBytes,
		ProcessLimit:       FixedProcessLimit,
		MaxLogBytes:        FixedMaxLogBytes,
	}
}
