// Command wardveil-negative-acceptance expands GoreeCloud Drive's target-environment
// Wardveil Scan failure-path evidence without modifying the deployed scanner backend.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/GoreeCloud/goreecloud-drive/internal/storage"
	"github.com/GoreeCloud/goreecloud-drive/internal/uploads"
	"github.com/GoreeCloud/goreecloud-drive/internal/wardveil"
)

type evidence struct {
	Component                      string       `json:"component"`
	DriveRevision                  string       `json:"drive_revision"`
	WardveilEndpoint               string       `json:"wardveil_endpoint"`
	WardveilRevision               string       `json:"wardveil_revision"`
	WardveilRestartEvidenceSHA256  string       `json:"wardveil_restart_evidence_sha256"`
	WardveilRestartEvidenceAt      time.Time    `json:"wardveil_restart_evidence_observed_at"`
	RuntimeNegativeMatrix          string       `json:"runtime_negative_matrix"`
	LiveWardveilCases              []string     `json:"live_wardveil_cases"`
	ValidatedWardveilRuntimeCases  []string     `json:"validated_wardveil_runtime_evidence"`
	ControlledDriveCases           []string     `json:"controlled_drive_cases"`
	ScannerTimeoutFailClosed       string       `json:"scanner_timeout_fail_closed"`
	ExpiredEvidenceFailClosed      decisionCase `json:"expired_evidence_fail_closed"`
	DigestMismatchFailClosed       decisionCase `json:"digest_mismatch_fail_closed"`
	ChangedDuringScanFailClosed    decisionCase `json:"changed_during_scan_fail_closed"`
	SuspiciousContentHeld          decisionCase `json:"suspicious_content_held"`
	UnknownResultFailClosed        decisionCase `json:"unknown_result_fail_closed"`
	UnsupportedResultFailClosed    decisionCase `json:"unsupported_result_fail_closed"`
	ExactReplayCached              string       `json:"exact_replay_cached"`
	ConflictingReplayRejected      string       `json:"conflicting_replay_rejected"`
	ReplayDurability               string       `json:"replay_durability"`
	MultiHostReplayDurability      string       `json:"multi_host_replay_durability"`
	RevokedCredential              string       `json:"revoked_credential"`
	StaleSignatures                string       `json:"stale_signatures"`
	CapacityExhaustion             string       `json:"capacity_exhaustion"`
	ProductionRuntimeAcceptance    string       `json:"production_runtime_acceptance"`
	ObservedAt                     time.Time    `json:"observed_at"`
}

type decisionCase struct {
	Status          string               `json:"status"`
	Disposition     wardveil.Disposition `json:"disposition"`
	CanRelease      bool                 `json:"can_release"`
	ObjectPublished bool                 `json:"object_published"`
	StagingHeld     bool                 `json:"staging_held"`
	ReasonCodes     []string             `json:"reason_codes"`
}

type scannerFunc func(context.Context, wardveil.ScanRequest, io.Reader) (wardveil.ScanEnvelope, error)

func (f scannerFunc) Scan(ctx context.Context, request wardveil.ScanRequest, body io.Reader) (wardveil.ScanEnvelope, error) {
	return f(ctx, request, body)
}

type recordingGate struct {
	delegate wardveil.StagedFileGate
	last     wardveil.Decision
}

func (g *recordingGate) EvaluateUpload(ctx context.Context, spaceID, uploadID, nodeID string) (wardveil.Decision, error) {
	decision, err := g.delegate.EvaluateUpload(ctx, spaceID, uploadID, nodeID)
	if err == nil {
		g.last = decision
	}
	return decision, err
}

func main() {
	var endpoint string
	var secretFile string
	var callerID string
	var keyID string
	var revision string
	var wardveilRevision string
	var wardveilRestartEvidence string
	var output string
	flag.StringVar(&endpoint, "endpoint", "http://127.0.0.1:8791/v1/scan", "deployed Wardveil Scan endpoint")
	flag.StringVar(&secretFile, "secret-file", "", "owner-only file containing the Drive Wardveil Scan caller secret")
	flag.StringVar(&callerID, "caller-id", "goreecloud-drive", "Wardveil Scan caller ID")
	flag.StringVar(&keyID, "key-id", "scan-current", "Wardveil Scan key ID")
	flag.StringVar(&revision, "source-revision", "", "exact GoreeCloud Drive source revision under acceptance")
	flag.StringVar(&wardveilRevision, "wardveil-revision", "", "exact deployed Wardveil Scan source revision")
	flag.StringVar(&wardveilRestartEvidence, "wardveil-restart-evidence", "", "private sanitized Wardveil Scan restart acceptance evidence file")
	flag.StringVar(&output, "output", "", "optional sanitized evidence output path")
	flag.Parse()

	if secretFile == "" || revision == "" || wardveilRevision == "" || wardveilRestartEvidence == "" {
		fatalf("--secret-file, --source-revision, --wardveil-revision, and --wardveil-restart-evidence are required")
	}
	secret, err := readSecretFile(secretFile)
	if err != nil {
		fatalf("read Wardveil Scan secret: %v", err)
	}

	now := time.Now().UTC()
	replayBinding, err := validateWardveilRestartEvidence(
		wardveilRestartEvidence,
		wardveilRevision,
		endpoint,
		callerID,
		keyID,
		now,
	)
	if err != nil {
		fatalf("validate Wardveil restart evidence: %v", err)
	}

	root, err := os.MkdirTemp("", "goreecloud-drive-wardveil-negative-acceptance-")
	if err != nil {
		fatalf("create negative acceptance storage: %v", err)
	}
	defer os.RemoveAll(root)
	store, err := storage.NewLocal(root)
	if err != nil {
		fatalf("initialize negative acceptance storage: %v", err)
	}
	if err := store.EnsureLayout(); err != nil {
		fatalf("initialize negative acceptance layout: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	timeoutStatus, err := runTimeoutCase(ctx, store, callerID, keyID, secret)
	if err != nil {
		fatalf("scanner timeout acceptance: %v", err)
	}
	expired, err := runControlledDecisionCase(ctx, store, now, "expired", func(request wardveil.ScanRequest) wardveil.ScanEnvelope {
		return authoritativeEnvelope(request, now.Add(-2*time.Minute), now.Add(-time.Minute), wardveil.ResultClean)
	}, wardveil.DispositionBlockedUnverified, "wardveil_evidence_expired")
	if err != nil {
		fatalf("expired evidence acceptance: %v", err)
	}
	digestMismatch, err := runControlledDecisionCase(ctx, store, now, "digest-mismatch", func(request wardveil.ScanRequest) wardveil.ScanEnvelope {
		envelope := authoritativeEnvelope(request, now.Add(-time.Second), now.Add(time.Minute), wardveil.ResultClean)
		envelope.ResourceDigestSHA256 = strings.Repeat("f", 64)
		return envelope
	}, wardveil.DispositionBlockedUnverified, "wardveil_digest_mismatch")
	if err != nil {
		fatalf("digest mismatch acceptance: %v", err)
	}
	changedDuringScan, err := runChangedDuringScanCase(ctx, store, now)
	if err != nil {
		fatalf("changed-during-scan acceptance: %v", err)
	}
	suspicious, err := runControlledDecisionCase(ctx, store, now, "suspicious", func(request wardveil.ScanRequest) wardveil.ScanEnvelope {
		return authoritativeEnvelope(request, now.Add(-time.Second), now.Add(time.Minute), wardveil.ResultSuspicious)
	}, wardveil.DispositionHoldReview, "wardveil_suspicious_review_required")
	if err != nil {
		fatalf("suspicious result acceptance: %v", err)
	}
	unknown, err := runControlledDecisionCase(ctx, store, now, "unknown", func(request wardveil.ScanRequest) wardveil.ScanEnvelope {
		return authoritativeEnvelope(request, now.Add(-time.Second), now.Add(time.Minute), wardveil.ResultUnknown)
	}, wardveil.DispositionBlockedUnverified, "wardveil_result_unknown")
	if err != nil {
		fatalf("unknown result acceptance: %v", err)
	}
	unsupported, err := runControlledDecisionCase(ctx, store, now, "unsupported", func(request wardveil.ScanRequest) wardveil.ScanEnvelope {
		return authoritativeEnvelope(request, now.Add(-time.Second), now.Add(time.Minute), wardveil.ResultUnsupported)
	}, wardveil.DispositionBlockedUnverified, "wardveil_result_unsupported")
	if err != nil {
		fatalf("unsupported result acceptance: %v", err)
	}
	exactReplay, conflictingReplay, err := runReplayCases(ctx, endpoint, callerID, keyID, secret)
	if err != nil {
		fatalf("replay acceptance: %v", err)
	}

	result := evidence{
		Component:                     "GoreeCloud Drive Wardveil Scan runtime negative acceptance",
		DriveRevision:                 revision,
		WardveilEndpoint:              endpoint,
		WardveilRevision:              replayBinding.WardveilRevision,
		WardveilRestartEvidenceSHA256: replayBinding.EvidenceSHA256,
		WardveilRestartEvidenceAt:     replayBinding.ObservedAt,
		RuntimeNegativeMatrix:         "passed",
		LiveWardveilCases:             []string{"exact_replay_cached", "conflicting_replay_rejected"},
		ValidatedWardveilRuntimeCases: []string{"single_host_restart_durability"},
		ControlledDriveCases:          []string{"scanner_timeout_fail_closed", "expired_evidence_fail_closed", "digest_mismatch_fail_closed", "changed_during_scan_fail_closed", "suspicious_content_held", "unknown_result_fail_closed", "unsupported_result_fail_closed"},
		ScannerTimeoutFailClosed:      timeoutStatus,
		ExpiredEvidenceFailClosed:     expired,
		DigestMismatchFailClosed:      digestMismatch,
		ChangedDuringScanFailClosed:   changedDuringScan,
		SuspiciousContentHeld:         suspicious,
		UnknownResultFailClosed:       unknown,
		UnsupportedResultFailClosed:   unsupported,
		ExactReplayCached:             exactReplay,
		ConflictingReplayRejected:     conflictingReplay,
		ReplayDurability:              replayBinding.ReplayDurability,
		MultiHostReplayDurability:     replayBinding.MultiHostReplayStatus,
		RevokedCredential:             "not_proven",
		StaleSignatures:               "not_proven",
		CapacityExhaustion:            "not_proven",
		ProductionRuntimeAcceptance:   "unaccepted",
		ObservedAt:                    time.Now().UTC(),
	}

	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fatalf("encode negative acceptance evidence: %v", err)
	}
	raw = append(raw, '\n')
	if output != "" {
		if err := os.WriteFile(output, raw, 0o600); err != nil {
			fatalf("write negative acceptance evidence: %v", err)
		}
	}
	_, _ = os.Stdout.Write(raw)
}

func runTimeoutCase(ctx context.Context, store *storage.Local, callerID, keyID, secret string) (string, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	server := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(500 * time.Millisecond)
	})}
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Close()

	scanner, err := wardveil.NewHTTPScanner(wardveil.HTTPScannerConfig{
		Endpoint: "http://" + listener.Addr().String() + wardveil.WardveilScanPath,
		CallerID: callerID,
		KeyID:    keyID,
		Secret:   secret,
		Timeout:  100 * time.Millisecond,
	})
	if err != nil {
		return "", err
	}
	return runUnavailableCase(ctx, store, scanner)
}

func runUnavailableCase(ctx context.Context, store *storage.Local, scanner wardveil.Scanner) (string, error) {
	spaceID, err := newUUID()
	if err != nil {
		return "", err
	}
	nodeID, err := newUUID()
	if err != nil {
		return "", err
	}
	gate := &recordingGate{delegate: wardveil.StagedFileGate{Store: store, Scanner: scanner}}
	service := uploads.New(uploads.NewMemoryRepository(), store, gate, 8<<20, 10*time.Minute)
	session, err := service.Create(ctx, "acceptance-account", spaceID, nodeID, "", "timeout.bin")
	if err != nil {
		return "", err
	}
	content := []byte("GoreeCloud Drive Wardveil timeout acceptance control\n")
	if _, err := service.Append(ctx, "acceptance-account", spaceID, session.ID, 0, bytes.NewReader(content)); err != nil {
		return "", err
	}
	_, completeErr := service.Complete(ctx, "acceptance-account", spaceID, session.ID)
	if !errors.Is(completeErr, uploads.ErrSecurityUnavailable) {
		return "", fmt.Errorf("expected fail-closed security unavailable, got %v", completeErr)
	}
	objectPath, err := store.ObjectPath(spaceID, nodeID)
	if err != nil {
		return "", err
	}
	stagingPath, err := store.StagingPath(spaceID, session.ID)
	if err != nil {
		return "", err
	}
	if exists(objectPath) || !exists(stagingPath) {
		return "", fmt.Errorf("timeout path did not preserve unpublished staged content")
	}
	return "passed", nil
}

func runControlledDecisionCase(
	ctx context.Context,
	store *storage.Local,
	now time.Time,
	name string,
	makeEnvelope func(wardveil.ScanRequest) wardveil.ScanEnvelope,
	expectedDisposition wardveil.Disposition,
	expectedReason string,
) (decisionCase, error) {
	spaceID, err := newUUID()
	if err != nil {
		return decisionCase{}, err
	}
	nodeID, err := newUUID()
	if err != nil {
		return decisionCase{}, err
	}
	scanner := scannerFunc(func(_ context.Context, request wardveil.ScanRequest, body io.Reader) (wardveil.ScanEnvelope, error) {
		if _, err := io.Copy(io.Discard, body); err != nil {
			return wardveil.ScanEnvelope{}, err
		}
		return makeEnvelope(request), nil
	})
	gate := &recordingGate{delegate: wardveil.StagedFileGate{Store: store, Scanner: scanner, Now: func() time.Time { return now }}}
	service := uploads.New(uploads.NewMemoryRepository(), store, gate, 8<<20, 10*time.Minute)
	session, err := service.Create(ctx, "acceptance-account", spaceID, nodeID, "", name+".bin")
	if err != nil {
		return decisionCase{}, err
	}
	content := []byte("GoreeCloud Drive controlled Wardveil " + name + " acceptance control\n")
	if _, err := service.Append(ctx, "acceptance-account", spaceID, session.ID, 0, bytes.NewReader(content)); err != nil {
		return decisionCase{}, err
	}
	_, completeErr := service.Complete(ctx, "acceptance-account", spaceID, session.ID)
	return validateBlockedDecision(store, spaceID, nodeID, session.ID, completeErr, expectedDisposition, expectedReason)
}

func runChangedDuringScanCase(ctx context.Context, store *storage.Local, now time.Time) (decisionCase, error) {
	spaceID, err := newUUID()
	if err != nil {
		return decisionCase{}, err
	}
	nodeID, err := newUUID()
	if err != nil {
		return decisionCase{}, err
	}
	var stagingPath string
	scanner := scannerFunc(func(_ context.Context, request wardveil.ScanRequest, body io.Reader) (wardveil.ScanEnvelope, error) {
		if _, err := io.Copy(io.Discard, body); err != nil {
			return wardveil.ScanEnvelope{}, err
		}
		if stagingPath == "" {
			return wardveil.ScanEnvelope{}, errors.New("changed-during-scan staging path unavailable")
		}
		if err := os.WriteFile(stagingPath, []byte("changed after Wardveil inspection\n"), 0o600); err != nil {
			return wardveil.ScanEnvelope{}, err
		}
		return authoritativeEnvelope(request, now.Add(-time.Second), now.Add(time.Minute), wardveil.ResultClean), nil
	})
	gate := &recordingGate{delegate: wardveil.StagedFileGate{Store: store, Scanner: scanner, Now: func() time.Time { return now }}}
	service := uploads.New(uploads.NewMemoryRepository(), store, gate, 8<<20, 10*time.Minute)
	session, err := service.Create(ctx, "acceptance-account", spaceID, nodeID, "", "changed-during-scan.bin")
	if err != nil {
		return decisionCase{}, err
	}
	stagingPath, err = store.StagingPath(spaceID, session.ID)
	if err != nil {
		return decisionCase{}, err
	}
	content := []byte("GoreeCloud Drive changed-during-scan acceptance control\n")
	if _, err := service.Append(ctx, "acceptance-account", spaceID, session.ID, 0, bytes.NewReader(content)); err != nil {
		return decisionCase{}, err
	}
	_, completeErr := service.Complete(ctx, "acceptance-account", spaceID, session.ID)
	return validateBlockedDecision(store, spaceID, nodeID, session.ID, completeErr, wardveil.DispositionBlockedUnverified, "drive_content_changed_during_scan")
}

func validateBlockedDecision(
	store *storage.Local,
	spaceID, nodeID, uploadID string,
	completeErr error,
	expectedDisposition wardveil.Disposition,
	expectedReason string,
) (decisionCase, error) {
	if !errors.Is(completeErr, uploads.ErrSecurityBlocked) {
		return decisionCase{}, fmt.Errorf("expected security block, got %v", completeErr)
	}
	var blocked *uploads.SecurityBlockedError
	if !errors.As(completeErr, &blocked) {
		return decisionCase{}, errors.New("security block did not preserve Wardveil decision")
	}
	if blocked.Decision.Disposition != expectedDisposition || blocked.Decision.CanRelease || !contains(blocked.Decision.ReasonCodes, expectedReason) {
		return decisionCase{}, fmt.Errorf("unexpected Wardveil decision: disposition=%s reasons=%v", blocked.Decision.Disposition, blocked.Decision.ReasonCodes)
	}
	objectPath, err := store.ObjectPath(spaceID, nodeID)
	if err != nil {
		return decisionCase{}, err
	}
	stagingPath, err := store.StagingPath(spaceID, uploadID)
	if err != nil {
		return decisionCase{}, err
	}
	objectPublished := exists(objectPath)
	stagingHeld := exists(stagingPath)
	if objectPublished || !stagingHeld {
		return decisionCase{}, errors.New("blocked upload did not remain unpublished and staged")
	}
	return decisionCase{
		Status:          "passed",
		Disposition:     blocked.Decision.Disposition,
		CanRelease:      blocked.Decision.CanRelease,
		ObjectPublished: objectPublished,
		StagingHeld:     stagingHeld,
		ReasonCodes:     append([]string(nil), blocked.Decision.ReasonCodes...),
	}, nil
}

func runReplayCases(ctx context.Context, endpoint, callerID, keyID, secret string) (string, string, error) {
	fixedTime := time.Now().UTC()
	nonce, err := randomToken("drive-replay-nonce")
	if err != nil {
		return "", "", err
	}
	correlationID, err := randomToken("drive-replay-correlation")
	if err != nil {
		return "", "", err
	}
	scanner, err := wardveil.NewHTTPScanner(wardveil.HTTPScannerConfig{
		Endpoint: endpoint,
		CallerID: callerID,
		KeyID:    keyID,
		Secret:   secret,
		Timeout:  10 * time.Second,
		Now:      func() time.Time { return fixedTime },
		Nonce:    func() (string, error) { return nonce, nil },
		CorrelationID: func() (string, error) {
			return correlationID, nil
		},
	})
	if err != nil {
		return "", "", err
	}
	spaceID, err := newUUID()
	if err != nil {
		return "", "", err
	}
	nodeID, err := newUUID()
	if err != nil {
		return "", "", err
	}
	resourceID := "drive:" + spaceID + ":file:" + nodeID
	content := []byte("GoreeCloud Drive exact replay acceptance control\n")
	digest := sha256.Sum256(content)
	request := wardveil.ScanRequest{
		ResourceType: wardveil.DriveFileResourceType,
		ResourceID:   resourceID,
		DigestSHA256: hex.EncodeToString(digest[:]),
		SizeBytes:    int64(len(content)),
		Action:       wardveil.ActionUploadFinalize,
	}
	first, err := scanner.Scan(ctx, request, bytes.NewReader(content))
	if err != nil {
		return "", "", fmt.Errorf("first replay request: %w", err)
	}
	second, err := scanner.Scan(ctx, request, bytes.NewReader(content))
	if err != nil {
		return "", "", fmt.Errorf("exact replay request: %w", err)
	}
	if !reflect.DeepEqual(first, second) {
		return "", "", errors.New("exact replay did not return the cached equivalent envelope")
	}

	conflictingContent := []byte("GoreeCloud Drive conflicting replay acceptance control\n")
	conflictingDigest := sha256.Sum256(conflictingContent)
	conflictingRequest := request
	conflictingRequest.DigestSHA256 = hex.EncodeToString(conflictingDigest[:])
	conflictingRequest.SizeBytes = int64(len(conflictingContent))
	_, conflictErr := scanner.Scan(ctx, conflictingRequest, bytes.NewReader(conflictingContent))
	if conflictErr == nil || !strings.Contains(conflictErr.Error(), "HTTP 409") {
		return "", "", fmt.Errorf("conflicting replay was not rejected with HTTP 409: %v", conflictErr)
	}
	return "passed", "passed", nil
}

func authoritativeEnvelope(request wardveil.ScanRequest, observedAt, validUntil time.Time, result wardveil.Result) wardveil.ScanEnvelope {
	return wardveil.ScanEnvelope{
		ResourceID:           request.ResourceID,
		ResourceDigestSHA256: request.DigestSHA256,
		ScanRecord: wardveil.ScanRecord{
			ContractVersion: wardveil.RuntimeContractVersion,
			RecordID:        "controlled-acceptance-record",
			RecordType:      wardveil.ScanRecordType,
			Producer:        wardveil.Producer{ID: "controlled-acceptance", Authoritative: true},
			Scope:           wardveil.Scope{ResourceType: wardveil.DriveFileResourceType, ResourceID: request.ResourceID},
			ObservedAt:      observedAt.UTC(),
			ValidUntil:      validUntil.UTC(),
			Result:          result,
			EvidenceRefs:    []string{"controlled:wardveil-negative-acceptance"},
		},
	}
}

func readSecretFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("secret file must be regular")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("secret file must not be readable or writable by group or others")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(raw) > 4096 {
		return "", errors.New("secret file exceeds 4096 bytes")
	}
	secret := strings.TrimSpace(string(raw))
	if secret == "" || strings.ContainsAny(secret, "\r\n") {
		return "", errors.New("secret file must contain one non-empty credential value")
	}
	return secret, nil
}

func randomToken(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(raw[:]), nil
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate acceptance UUID: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
