// Command wardveil-acceptance exercises GoreeCloud Drive's real upload-finalization
// path against a deployed Wardveil Scan transport and emits sanitized evidence.
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
	"os"
	"strings"
	"time"

	"github.com/GoreeCloud/goreecloud-drive/internal/storage"
	"github.com/GoreeCloud/goreecloud-drive/internal/uploads"
	"github.com/GoreeCloud/goreecloud-drive/internal/wardveil"
)

const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

type evidence struct {
	Component                      string       `json:"component"`
	DriveRevision                  string       `json:"drive_revision"`
	WardveilEndpoint               string       `json:"wardveil_endpoint"`
	ApplicationConsumerIntegration string       `json:"application_consumer_integration"`
	CleanUploadFinalize            caseEvidence `json:"clean_upload_finalize"`
	MaliciousUploadFinalize        caseEvidence `json:"malicious_upload_finalize"`
	InvalidCredentialFailClosed    string       `json:"invalid_credential_fail_closed"`
	ScannerUnavailableFailClosed   string       `json:"scanner_unavailable_fail_closed"`
	DirectClamAVAccess             bool         `json:"direct_clamav_access"`
	QuarantineExecution            string       `json:"quarantine_execution"`
	ProductionServiceIdentity      string       `json:"production_service_identity"`
	ProductionRuntimeAcceptance    string       `json:"production_runtime_acceptance"`
	ObservedAt                     time.Time    `json:"observed_at"`
}

type caseEvidence struct {
	Completed                         bool                 `json:"completed"`
	Disposition                       wardveil.Disposition `json:"disposition"`
	CanRelease                        bool                 `json:"can_release"`
	QuarantineRequired                bool                 `json:"quarantine_required"`
	ObjectPublished                   bool                 `json:"object_published"`
	StagingHeld                       bool                 `json:"staging_held"`
	PublishedBytesMatch               bool                 `json:"published_bytes_match"`
	QuarantineHandoffGenerated        bool                 `json:"quarantine_handoff_generated"`
	RequiresExplicitExecutorAuthority bool                 `json:"requires_explicit_executor_authority"`
	DestructiveAction                 bool                 `json:"destructive_action"`
	ReasonCodes                       []string             `json:"reason_codes"`
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
	var output string
	flag.StringVar(&endpoint, "endpoint", "http://127.0.0.1:8791/v1/scan", "Wardveil Scan endpoint")
	flag.StringVar(&secretFile, "secret-file", "", "owner-only file containing the Drive Wardveil Scan caller secret")
	flag.StringVar(&callerID, "caller-id", "goreecloud-drive", "Wardveil Scan caller ID")
	flag.StringVar(&keyID, "key-id", "scan-current", "Wardveil Scan key ID")
	flag.StringVar(&revision, "source-revision", "", "exact GoreeCloud Drive source revision under acceptance")
	flag.StringVar(&output, "output", "", "optional sanitized evidence output path")
	flag.Parse()

	if secretFile == "" || revision == "" {
		fatalf("--secret-file and --source-revision are required")
	}
	secret, err := readSecretFile(secretFile)
	if err != nil {
		fatalf("read Wardveil Scan secret: %v", err)
	}

	scanner, err := wardveil.NewHTTPScanner(wardveil.HTTPScannerConfig{
		Endpoint: endpoint,
		CallerID: callerID,
		KeyID:    keyID,
		Secret:   secret,
		Timeout:  10 * time.Second,
	})
	if err != nil {
		fatalf("initialize Wardveil Scan client: %v", err)
	}

	root, err := os.MkdirTemp("", "goreecloud-drive-wardveil-acceptance-")
	if err != nil {
		fatalf("create acceptance storage: %v", err)
	}
	defer os.RemoveAll(root)
	store, err := storage.NewLocal(root)
	if err != nil {
		fatalf("initialize acceptance storage: %v", err)
	}
	if err := store.EnsureLayout(); err != nil {
		fatalf("initialize acceptance storage layout: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	cleanEvidence, err := runUploadCase(ctx, store, scanner, []byte("GoreeCloud Drive live Wardveil clean acceptance control\n"), true)
	if err != nil {
		fatalf("clean upload acceptance: %v", err)
	}
	maliciousEvidence, err := runUploadCase(ctx, store, scanner, []byte(eicar), false)
	if err != nil {
		fatalf("malicious upload acceptance: %v", err)
	}
	invalidCredential, err := runNegativeCase(ctx, store, endpoint, callerID, keyID, strings.Repeat("0", 64))
	if err != nil {
		fatalf("invalid credential acceptance: %v", err)
	}
	unavailableEndpoint, err := runNegativeCase(ctx, store, "http://127.0.0.1:8792/v1/scan", callerID, keyID, secret)
	if err != nil {
		fatalf("scanner unavailable acceptance: %v", err)
	}

	result := evidence{
		Component:                      "GoreeCloud Drive Wardveil Scan live application acceptance",
		DriveRevision:                  revision,
		WardveilEndpoint:               endpoint,
		ApplicationConsumerIntegration: "passed",
		CleanUploadFinalize:            cleanEvidence,
		MaliciousUploadFinalize:        maliciousEvidence,
		InvalidCredentialFailClosed:    invalidCredential,
		ScannerUnavailableFailClosed:   unavailableEndpoint,
		DirectClamAVAccess:             false,
		QuarantineExecution:            "not_proven",
		ProductionServiceIdentity:      "not_proven",
		ProductionRuntimeAcceptance:    "unaccepted",
		ObservedAt:                     time.Now().UTC(),
	}

	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fatalf("encode acceptance evidence: %v", err)
	}
	raw = append(raw, '\n')
	if output != "" {
		if err := os.WriteFile(output, raw, 0o600); err != nil {
			fatalf("write acceptance evidence: %v", err)
		}
	}
	_, _ = os.Stdout.Write(raw)
}

func runUploadCase(ctx context.Context, store *storage.Local, scanner wardveil.Scanner, content []byte, expectClean bool) (caseEvidence, error) {
	spaceID, err := newUUID()
	if err != nil {
		return caseEvidence{}, err
	}
	nodeID, err := newUUID()
	if err != nil {
		return caseEvidence{}, err
	}
	gate := &recordingGate{delegate: wardveil.StagedFileGate{Store: store, Scanner: scanner}}
	service := uploads.New(uploads.NewMemoryRepository(), store, gate, 8<<20, 10*time.Minute)
	session, err := service.Create(ctx, "acceptance-account", spaceID, nodeID, "", "acceptance.bin")
	if err != nil {
		return caseEvidence{}, err
	}
	if _, err := service.Append(ctx, "acceptance-account", spaceID, session.ID, 0, bytes.NewReader(content)); err != nil {
		return caseEvidence{}, err
	}
	completed, completeErr := service.Complete(ctx, "acceptance-account", spaceID, session.ID)

	objectPath, err := store.ObjectPath(spaceID, nodeID)
	if err != nil {
		return caseEvidence{}, err
	}
	stagingPath, err := store.StagingPath(spaceID, session.ID)
	if err != nil {
		return caseEvidence{}, err
	}
	objectPublished := exists(objectPath)
	stagingHeld := exists(stagingPath)

	result := caseEvidence{
		Disposition:        gate.last.Disposition,
		CanRelease:         gate.last.CanRelease,
		QuarantineRequired: gate.last.QuarantineRequired,
		ObjectPublished:    objectPublished,
		StagingHeld:        stagingHeld,
		ReasonCodes:        append([]string(nil), gate.last.ReasonCodes...),
	}

	if expectClean {
		if completeErr != nil {
			return caseEvidence{}, completeErr
		}
		if completed.State != uploads.StateCompleted || gate.last.Disposition != wardveil.DispositionAllow || !gate.last.CanRelease || !objectPublished || stagingHeld {
			return caseEvidence{}, fmt.Errorf("clean upload did not complete with exact release semantics")
		}
		opened, err := store.OpenObject(spaceID, nodeID)
		if err != nil {
			return caseEvidence{}, err
		}
		published, readErr := io.ReadAll(opened)
		closeErr := opened.Close()
		if readErr != nil {
			return caseEvidence{}, readErr
		}
		if closeErr != nil {
			return caseEvidence{}, closeErr
		}
		result.Completed = true
		result.PublishedBytesMatch = bytes.Equal(published, content)
		if !result.PublishedBytesMatch {
			return caseEvidence{}, fmt.Errorf("published clean bytes did not match staged bytes")
		}
		return result, nil
	}

	if !errors.Is(completeErr, uploads.ErrSecurityBlocked) {
		return caseEvidence{}, fmt.Errorf("malicious upload did not fail with security block: %v", completeErr)
	}
	var blocked *uploads.SecurityBlockedError
	if !errors.As(completeErr, &blocked) {
		return caseEvidence{}, fmt.Errorf("malicious upload did not preserve Wardveil decision")
	}
	if blocked.Decision.Disposition != wardveil.DispositionBlockQuarantine || blocked.Decision.CanRelease || !blocked.Decision.QuarantineRequired || objectPublished || !stagingHeld {
		return caseEvidence{}, fmt.Errorf("malicious upload enforcement semantics were not preserved")
	}
	digest := sha256.Sum256(content)
	handoff, ok := blocked.Decision.QuarantineHandoff(wardveil.FileResource{
		SpaceID:      spaceID,
		NodeID:       nodeID,
		DigestSHA256: hex.EncodeToString(digest[:]),
		SizeBytes:    int64(len(content)),
	})
	if !ok || !handoff.RequiresExplicitExecutorAuthority || handoff.DestructiveAction {
		return caseEvidence{}, fmt.Errorf("quarantine handoff did not preserve explicit-authority non-destructive boundary")
	}
	result.QuarantineHandoffGenerated = true
	result.RequiresExplicitExecutorAuthority = handoff.RequiresExplicitExecutorAuthority
	result.DestructiveAction = handoff.DestructiveAction
	return result, nil
}

func runNegativeCase(ctx context.Context, store *storage.Local, endpoint, callerID, keyID, secret string) (string, error) {
	scanner, err := wardveil.NewHTTPScanner(wardveil.HTTPScannerConfig{
		Endpoint: endpoint,
		CallerID: callerID,
		KeyID:    keyID,
		Secret:   secret,
		Timeout:  2 * time.Second,
	})
	if err != nil {
		return "", err
	}
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
	session, err := service.Create(ctx, "acceptance-account", spaceID, nodeID, "", "negative.bin")
	if err != nil {
		return "", err
	}
	content := []byte("GoreeCloud Drive Wardveil negative acceptance control\n")
	if _, err := service.Append(ctx, "acceptance-account", spaceID, session.ID, 0, bytes.NewReader(content)); err != nil {
		return "", err
	}
	_, err = service.Complete(ctx, "acceptance-account", spaceID, session.ID)
	if !errors.Is(err, uploads.ErrSecurityUnavailable) {
		return "", fmt.Errorf("expected fail-closed security unavailable, got %v", err)
	}
	objectPath, pathErr := store.ObjectPath(spaceID, nodeID)
	if pathErr != nil {
		return "", pathErr
	}
	if exists(objectPath) {
		return "", fmt.Errorf("negative-path upload published content")
	}
	return "passed", nil
}

func readSecretFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("secret file must be regular")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("secret file must not be readable or writable by group or others")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(raw) > 4096 {
		return "", fmt.Errorf("secret file exceeds 4096 bytes")
	}
	secret := strings.TrimSpace(string(raw))
	if secret == "" || strings.ContainsAny(secret, "\r\n") {
		return "", fmt.Errorf("secret file must contain one non-empty credential value")
	}
	return secret, nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
