package devopsbuildv1

import (
	"bytes"
	"testing"
)

func TestControlDocumentsBindActionIdentityAndCompleteRequest(t *testing.T) {
	request := requestFixture([]byte("canonical source archive"))
	for _, action := range []ControlAction{ControlObserve, ControlCancel} {
		t.Run(string(action), func(t *testing.T) {
			content, err := EncodeControl(action, request)
			if err != nil {
				t.Fatalf("encode control: %v", err)
			}
			decodedAction, decodedRequest, err := DecodeControl(content)
			if err != nil || decodedAction != action || decodedRequest != request {
				t.Fatalf(
					"decode control = %q / %#v / %v",
					decodedAction,
					decodedRequest,
					err,
				)
			}
			for name, changed := range map[string][]byte{
				"identity": bytes.Replace(
					content,
					[]byte(`"executionId":"sha256:`),
					[]byte(`"executionId":"sha256:f`),
					1,
				),
				"unknown field": bytes.Replace(
					content,
					[]byte(`"request":`),
					[]byte(`"unexpected":true,"request":`),
					1,
				),
				"noncanonical": append([]byte(" "), content...),
			} {
				t.Run(name, func(t *testing.T) {
					if _, _, err := DecodeControl(changed); err == nil {
						t.Fatal("changed control document was accepted")
					}
				})
			}
		})
	}
	if _, err := EncodeControl("EXECUTE", request); err == nil {
		t.Fatal("unsupported control action was accepted")
	}
}

func TestObservationDocumentsCloseStateAndReceiptPair(t *testing.T) {
	request := requestFixture([]byte("canonical source archive"))
	executionID, err := ExecutionID(request)
	if err != nil {
		t.Fatal(err)
	}
	receipt := receiptFixture(
		request, ConclusionPassed, StepConclusionPassed, StepConclusionPassed,
	)
	for _, observation := range []Observation{
		{
			APIVersion: APIVersion, Kind: ObservationKind,
			ExecutionID: executionID, State: ExecutionQueued,
		},
		{
			APIVersion: APIVersion, Kind: ObservationKind,
			ExecutionID: executionID, State: ExecutionAssigned,
		},
		{
			APIVersion: APIVersion, Kind: ObservationKind,
			ExecutionID: executionID, State: ExecutionCancellationRequested,
		},
		{
			APIVersion: APIVersion, Kind: ObservationKind,
			ExecutionID: executionID, State: ExecutionTerminal, Receipt: &receipt,
		},
		{
			APIVersion: APIVersion, Kind: ObservationKind,
			ExecutionID: executionID, State: ExecutionCancelled,
		},
	} {
		t.Run(string(observation.State), func(t *testing.T) {
			content, err := EncodeObservation(request, observation)
			if err != nil {
				t.Fatalf("encode observation: %v", err)
			}
			decoded, err := DecodeObservation(request, content)
			if err != nil || decoded.State != observation.State ||
				(decoded.Receipt == nil) != (observation.Receipt == nil) {
				t.Fatalf("decode observation = %#v / %v", decoded, err)
			}
		})
	}

	invalid := []Observation{
		{
			APIVersion: APIVersion, Kind: ObservationKind,
			ExecutionID: executionID, State: ExecutionTerminal,
		},
		{
			APIVersion: APIVersion, Kind: ObservationKind,
			ExecutionID: executionID, State: ExecutionQueued, Receipt: &receipt,
		},
		{
			APIVersion: APIVersion, Kind: ObservationKind,
			ExecutionID: "sha256:changed", State: ExecutionQueued,
		},
	}
	for _, observation := range invalid {
		if _, err := EncodeObservation(request, observation); err == nil {
			t.Fatal("invalid observation state was accepted")
		}
	}
}
