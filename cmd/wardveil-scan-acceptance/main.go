package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GoreeCloud/goreecloud-drive/internal/wardveil"
)

type memoryStaging struct {
	content []byte
}

func (s memoryStaging) OpenStaging(_, _ string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(s.content)), nil
}

type checks struct {
	AuthenticatedCleanRelease bool `json:"authenticated_clean_release"`
	EICARBlockedQuarantine    bool `json:"eicar_block_quarantine"`
	QuarantineHandoff         bool `json:"quarantine_handoff_generated"`
	WrongTokenFailClosed      bool `json:"wrong_token_fail_closed"`
}

type evidence struct {
	SchemaVersion                  int    `json:"schema_version"`
	Component                      string `json:"component"`
	Environment                    string `json:"environment"`
	ObservedAt                     string `json:"observed_at"`
	DriveRevision                  string `json:"drive_revision"`
	WardveilRevision               string `json:"wardveil_revision"`
	Consumer                       string `json:"consumer"`
	Transport                      string `json:"transport"`
	Checks                         checks `json:"checks"`
	RuntimeEvidenceStatus          string `json:"runtime_evidence_status"`
	ApplicationConsumerIntegration string `json:"application_consumer_integration"`
	QuarantineExecutionEvidence    string `json:"quarantine_execution_evidence"`
	ProductionDriveAcceptance      string `json:"production_drive_acceptance"`
	ProtectionClaimAuthority       bool   `json:"protection_claim_authority"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Drive Wardveil Scan acceptance failed")
		os.Exit(1)
	}
}

func run() error {
	endpoint := flag.String("endpoint", os.Getenv("WARDVEIL_SCAN_ENDPOINT"), "Wardveil loopback Scan endpoint")
	driveRevision := flag.String("drive-revision", os.Getenv("GOREECLOUD_DRIVE_DEPLOYED_REVISION"), "exact GoreeCloud Drive source revision")
	wardveilRevision := flag.String("wardveil-revision", os.Getenv("WARDVEIL_DEPLOYED_REVISION"), "exact Wardveil source revision")
	output := flag.String("output", "", "optional sanitized JSON output path")
	flag.Parse()

	token := os.Getenv("WARDVEIL_SCAN_SERVICE_TOKEN")
	if !validRevision(*driveRevision) || !validRevision(*wardveilRevision) {
		return errors.New("source revision invalid")
	}
	scanner, err := wardveil.NewHTTPScanner(wardveil.HTTPScannerConfig{
		Endpoint: *endpoint,
		Token:    token,
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	result := checks{}

	cleanDecision, err := evaluate(ctx, scanner, []byte("GoreeCloud Drive controlled clean Wardveil acceptance sample\n"), "clean-node")
	if err == nil && cleanDecision.CanRelease && cleanDecision.Disposition == wardveil.DispositionAllow {
		result.AuthenticatedCleanRelease = true
	}

	eicar := eicarBytes()
	eicarDecision, err := evaluate(ctx, scanner, eicar, "eicar-node")
	if err == nil && !eicarDecision.CanRelease && eicarDecision.QuarantineRequired && eicarDecision.Disposition == wardveil.DispositionBlockQuarantine {
		result.EICARBlockedQuarantine = true
		resource := wardveil.FileResource{
			SpaceID:      acceptanceSpaceID,
			NodeID:       "eicar-node",
			DigestSHA256: digestFor(eicar),
			SizeBytes:    int64(len(eicar)),
		}
		handoff, ok := eicarDecision.QuarantineHandoff(resource)
		if ok && handoff.RequiresExplicitExecutorAuthority && !handoff.DestructiveAction && handoff.ResourceID == resource.ResourceID() && strings.EqualFold(handoff.DigestSHA256, resource.DigestSHA256) {
			result.QuarantineHandoff = true
		}
	}

	badScanner, err := wardveil.NewHTTPScanner(wardveil.HTTPScannerConfig{
		Endpoint: *endpoint,
		Token:    wrongToken(token),
	})
	if err != nil {
		return err
	}
	if _, err := evaluate(ctx, badScanner, []byte("GoreeCloud Drive authentication fail-closed sample\n"), "auth-node"); err != nil {
		result.WrongTokenFailClosed = true
	}

	passed := result.AuthenticatedCleanRelease && result.EICARBlockedQuarantine && result.QuarantineHandoff && result.WrongTokenFailClosed
	status := "failed"
	consumerIntegration := "unaccepted"
	if passed {
		status = "passed"
		consumerIntegration = "accepted"
	}
	manifest := evidence{
		SchemaVersion:                  1,
		Component:                      "GoreeCloud Drive Wardveil Scan consumer",
		Environment:                    "production",
		ObservedAt:                     time.Now().UTC().Format(time.RFC3339Nano),
		DriveRevision:                  *driveRevision,
		WardveilRevision:               *wardveilRevision,
		Consumer:                       "Drive StagedFileGate",
		Transport:                      "loopback_http_bearer",
		Checks:                         result,
		RuntimeEvidenceStatus:          status,
		ApplicationConsumerIntegration: consumerIntegration,
		QuarantineExecutionEvidence:    "unaccepted",
		ProductionDriveAcceptance:      "unaccepted",
		ProtectionClaimAuthority:       false,
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if *output != "" {
		if err := os.MkdirAll(filepath.Dir(*output), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(*output, encoded, 0o644); err != nil {
			return err
		}
	}
	if _, err := os.Stdout.Write(encoded); err != nil {
		return err
	}
	if !passed {
		return errors.New("acceptance checks failed")
	}
	return nil
}

const acceptanceSpaceID = "wardveil-acceptance-space"

func evaluate(ctx context.Context, scanner wardveil.Scanner, content []byte, nodeID string) (wardveil.Decision, error) {
	gate := wardveil.StagedFileGate{
		Store:   memoryStaging{content: content},
		Scanner: scanner,
		Now:     func() time.Time { return time.Now().UTC() },
	}
	return gate.EvaluateUpload(ctx, acceptanceSpaceID, "acceptance-upload", nodeID)
}

func eicarBytes() []byte {
	return []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
}

func digestFor(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func wrongToken(token string) string {
	if len([]byte(token)) < 32 {
		return strings.Repeat("x", 32)
	}
	return "invalid-" + token
}

func validRevision(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, char := range value {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}
