package phase1e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	nodev1 "github.com/xiak/matrix/api/adapter/node/v1"
	auditv1 "github.com/xiak/matrix/api/audit/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/test/websocketclient"
)

const (
	nativeTerminalRevisionID paasv1.ResourceID = "phase3-terminal-application-r7"
	terminalTicketCookieName                   = "matrix_terminal_ticket"
)

func (value *gate) createNativeTerminalApplicationRevision(
	ctx context.Context,
	bearer []byte,
) (paasv1.ResourceID, error) {
	workload, ok := workloadImage(value.releases.b.Manifest)
	if !ok {
		return "", fail("native-terminal-signed-workload")
	}
	request := paasv1.CreateApplicationRevisionRequest{
		ID: nativeTerminalRevisionID, Name: string(nativeTerminalRevisionID),
		Spec: paasv1.ApplicationRevisionSpec{
			ApplicationID: applicationID,
			Revision:      "revision-terminal-r7",
			ContentDigest: fixedDigest("phase3-terminal-application-r7"),
			Components: []paasv1.ApplicationRevisionComponent{
				verificationApplicationComponent(workload.SourceDigest),
			},
		},
	}
	if _, err := value.edge.createResource(
		ctx,
		"/api/paas/v1/application-revisions",
		"phase3-create-terminal-application-r7",
		bearer,
		request,
		paasv1.OperationCreateApplicationRevision,
		paasv1.ResourceRef{Kind: "ApplicationRevision", ID: nativeTerminalRevisionID},
	); err != nil {
		return "", fail("native-terminal-application-revision")
	}
	return nativeTerminalRevisionID, nil
}

func (value *gate) assertNativeTerminal(
	ctx context.Context,
	bearer []byte,
	deployment paasv1.Deployment,
	snapshot paasv1.DeploymentRuntimeSnapshot,
	index int,
) (paasv1.ResourceID, error) {
	if len(snapshot.Value.Observation.Instances) != 1 {
		return "", fail("native-terminal-current-instance")
	}
	instance := snapshot.Value.Observation.Instances[0]
	initialSize := paasv1.TerminalSize{Columns: 90, Rows: 30}
	response, err := value.edge.json(
		ctx,
		http.MethodPost,
		"/api/paas/v1/deployments/"+string(deployment.Metadata.ID)+"/terminal-sessions",
		bearer,
		paasv1.CreateTerminalSessionRequest{InstanceID: instance.ID, Size: initialSize},
		map[string]string{"Idempotency-Key": "phase3-native-terminal-" + strconv.Itoa(index+1)},
		http.StatusCreated,
	)
	if err != nil {
		return "", fail("native-terminal-create")
	}
	defer clear(response.body)
	var session paasv1.TerminalSession
	if decodeOne(response.body, &session) != nil || paasv1.ValidateTerminalSession(session) != nil ||
		session.State != paasv1.TerminalSessionPending || session.DeploymentID != deployment.Metadata.ID ||
		session.Generation != deployment.Generation || session.ApplicationRevisionID != deployment.Spec.ApplicationRevisionID ||
		session.InstanceID != instance.ID || session.Size != initialSize ||
		response.header.Get("Location") != "/api/paas/v1/terminal-sessions/"+string(session.ID) {
		return "", fail("native-terminal-create-contract")
	}
	connectPath := "/api/paas/v1/terminal-sessions/" + string(session.ID) + "/connect"
	cookie, err := exactTerminalTicketCookie(response.header, connectPath, session, strings.HasPrefix(value.edge.endpoint, "https://"))
	if err != nil || bytes.Contains(response.body, []byte(cookie.Value)) ||
		strings.Contains(response.header.Get("Location"), cookie.Value) {
		return "", fail("native-terminal-one-time-ticket")
	}
	ticket := []byte(cookie.Value)
	value.edge.addForbidden(ticket)
	value.sensitive = append(value.sensitive, ticket)
	cookieHeader := terminalTicketCookieName + "=" + cookie.Value
	cookie.Value = ""

	terminalContext, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	connection, _, err := websocketclient.Dial(
		terminalContext,
		value.edge.endpoint+connectPath,
		websocketclient.DialOptions{
			HTTPClient: value.edge.http,
			HTTPHeader: http.Header{
				"Cookie": []string{cookieHeader},
				"Origin": []string{value.edge.endpoint},
			},
			Subprotocol:     nodev1.TerminalSubprotocol,
			MaxMessageBytes: paasv1.MaximumTerminalFrameBytes,
		},
	)
	if err != nil || connection == nil || connection.Subprotocol() != nodev1.TerminalSubprotocol {
		if connection != nil {
			connection.CloseNow()
		}
		return "", fail("native-terminal-connect")
	}
	defer connection.CloseNow()
	ready, err := readNativeTerminalControl(terminalContext, connection)
	if err != nil || ready.Type != nodev1.TerminalServerReady {
		return "", fail("native-terminal-ready")
	}
	resized := paasv1.TerminalSize{Columns: 100, Rows: 35}
	resizeDocument, _ := json.Marshal(nodev1.TerminalClientControl{Type: nodev1.TerminalClientResize, Size: &resized})
	if err := connection.Write(terminalContext, websocketclient.MessageText, resizeDocument); err != nil {
		clear(resizeDocument)
		return "", fail("native-terminal-resize")
	}
	clear(resizeDocument)
	marker := "matrix-signed-terminal-ok-" + strconv.Itoa(index+1)
	command := []byte("stty size; printf '" + marker + "\\n'; exit\n")
	if err := connection.Write(terminalContext, websocketclient.MessageBinary, command); err != nil {
		clear(command)
		return "", fail("native-terminal-input")
	}
	clear(command)
	output, exitCode, err := readNativeTerminalResult(terminalContext, connection)
	defer clear(output)
	if err != nil || exitCode != 0 || len(output) > paasv1.MaximumTerminalFrameBytes ||
		!bytes.Contains(output, []byte("35 100")) || !bytes.Contains(output, []byte(marker)) {
		return "", fail("native-terminal-output-resize-exit")
	}
	connection.CloseNow()
	if err := rejectNativeTerminalReplay(terminalContext, value.edge, connectPath, cookieHeader); err != nil {
		return "", err
	}
	return session.ID, nil
}

func exactTerminalTicketCookie(
	header http.Header,
	connectPath string,
	session paasv1.TerminalSession,
	secure bool,
) (*http.Cookie, error) {
	values := header.Values("Set-Cookie")
	if len(values) != 1 {
		return nil, errors.New("one terminal ticket cookie is required")
	}
	cookie, err := http.ParseSetCookie(values[0])
	if err != nil || cookie.Name != terminalTicketCookieName || len(cookie.Value) != 43 ||
		cookie.Path != connectPath || cookie.Domain != "" || !cookie.HttpOnly || cookie.Secure != secure ||
		cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge != int(paasv1.TerminalSessionConnectTimeout.Seconds()) ||
		cookie.Expires.IsZero() || cookie.Expires.After(session.ConnectBefore.Add(time.Second)) {
		return nil, errors.New("terminal ticket cookie is invalid")
	}
	return cookie, nil
}

func readNativeTerminalControl(
	ctx context.Context,
	connection *websocketclient.Connection,
) (nodev1.TerminalServerControl, error) {
	kind, content, err := connection.Read(ctx)
	if err != nil || kind != websocketclient.MessageText {
		clear(content)
		return nodev1.TerminalServerControl{}, errors.New("terminal control frame is unavailable")
	}
	defer clear(content)
	return nodev1.DecodeTerminalServerControl(bytes.NewReader(content))
}

func readNativeTerminalResult(
	ctx context.Context,
	connection *websocketclient.Connection,
) ([]byte, int32, error) {
	output := make([]byte, 0, 4096)
	for count := 0; count < 32; count++ {
		kind, content, err := connection.Read(ctx)
		if err != nil {
			clear(content)
			clear(output)
			return nil, 0, errors.New("terminal result frame is unavailable")
		}
		switch kind {
		case websocketclient.MessageBinary:
			if len(content) == 0 || len(output)+len(content) > paasv1.MaximumTerminalFrameBytes {
				clear(content)
				clear(output)
				return nil, 0, errors.New("terminal output exceeded its bound")
			}
			output = append(output, content...)
			clear(content)
		case websocketclient.MessageText:
			control, decodeErr := nodev1.DecodeTerminalServerControl(bytes.NewReader(content))
			clear(content)
			if decodeErr != nil || control.Type != nodev1.TerminalServerExit || control.ExitCode == nil {
				clear(output)
				return nil, 0, errors.New("terminal exit control is invalid")
			}
			return output, *control.ExitCode, nil
		default:
			clear(content)
			clear(output)
			return nil, 0, errors.New("terminal result frame type is invalid")
		}
	}
	clear(output)
	return nil, 0, errors.New("terminal result exceeded its frame bound")
}

func rejectNativeTerminalReplay(
	ctx context.Context,
	client *edgeClient,
	connectPath string,
	cookieHeader string,
) error {
	connection, response, err := websocketclient.Dial(
		ctx,
		client.endpoint+connectPath,
		websocketclient.DialOptions{
			HTTPClient: client.http,
			HTTPHeader: http.Header{
				"Cookie": []string{cookieHeader},
				"Origin": []string{client.endpoint},
			},
			Subprotocol:     nodev1.TerminalSubprotocol,
			MaxMessageBytes: paasv1.MaximumTerminalFrameBytes,
		},
	)
	if connection != nil {
		connection.CloseNow()
	}
	if err == nil || response == nil || response.StatusCode != http.StatusConflict {
		return fail("native-terminal-ticket-replay")
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	content, readErr := io.ReadAll(response.Body)
	defer clear(content)
	var problem paasv1.Problem
	if readErr != nil || mediaErr != nil || mediaType != "application/problem+json" ||
		containsAny(content, client.forbidden) || decodeOne(content, &problem) != nil ||
		paasv1.ValidateProblem(problem) != nil || problem.Status != http.StatusConflict ||
		problem.Code != paasv1.ErrorConflict {
		return fail("native-terminal-ticket-replay-contract")
	}
	return nil
}

func (value *gate) assertNativeTerminalAudit(
	ctx context.Context,
	bearer []byte,
	sessionIDs []paasv1.ResourceID,
) error {
	if len(sessionIDs) != 2 || sessionIDs[0] == sessionIDs[1] {
		return fail("native-terminal-audit-input")
	}
	want := map[auditv1.Action]auditv1.Result{
		auditv1.ActionPaaSTerminalSessionCreated: auditv1.ResultAccepted,
		auditv1.ActionPaaSTerminalSessionStarted: auditv1.ResultSucceeded,
		auditv1.ActionPaaSTerminalSessionEnded:   auditv1.ResultCompleted,
	}
	poll, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	for poll.Err() == nil {
		records, err := value.edge.allAuditRecords(poll, bearer)
		found := make(map[paasv1.ResourceID]map[auditv1.Action]bool, len(sessionIDs))
		for _, id := range sessionIDs {
			found[id] = make(map[auditv1.Action]bool, len(want))
		}
		valid := err == nil
		for _, record := range records {
			id := paasv1.ResourceID(record.Event.Target.ID)
			actions, relevant := found[id]
			result, expectedAction := want[record.Event.Action]
			if !relevant || !expectedAction {
				continue
			}
			if record.Source != auditv1.SourcePaaS || record.Event.Target.Kind != auditv1.TargetTerminalSession ||
				record.Event.Result != result || record.Event.TenantID != auditv1.TenantID("organization-default") ||
				record.Event.Actor.Type != auditv1.ActorUser || record.Event.Actor.ID != auditv1.ActorID("principal-admin") ||
				record.Event.IAMDecisionID == "" || record.Event.OperationID != "" {
				valid = false
				break
			}
			actions[record.Event.Action] = true
		}
		complete := valid
		for _, actions := range found {
			for action := range want {
				complete = complete && actions[action]
			}
		}
		if complete {
			encoded, encodeErr := json.Marshal(records)
			if encodeErr != nil || bytes.Contains(encoded, []byte("stty size")) ||
				bytes.Contains(encoded, []byte("matrix-signed-terminal-ok")) {
				clear(encoded)
				return fail("native-terminal-audit-redaction")
			}
			clear(encoded)
			emit("two-signed-native-terminal-sessions-with-resize-replay-and-audit")
			return nil
		}
		if !waitPoll(poll, 250*time.Millisecond) {
			break
		}
	}
	return fail("native-terminal-audit")
}
