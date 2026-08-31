package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testWardveilRevision = "053c7fd81db3011cf1d7b7b304d4b33413e97e4b"
const testWardveilEndpoint = "http://127.0.0.1:8791/v1/scan"

func validRestartEvidence(now time.Time) wardveilRestartEvidence {
	return wardveilRestartEvidence{
		Component:                        "Wardveil Scan durable same-host replay restart acceptance",
		WardveilRevision:                 testWardveilRevision,
		WardveilEndpoint:                 testWardveilEndpoint,
		Service:                          "wardveil-scan.service",
		CallerID:                         "goreecloud-drive",
		KeyID:                            "scan-current",
		ResourceType:                     "drive_file",
		InitialAuthenticatedCleanRequest: "passed",
		ServiceRestart:                   "passed",
		SystemdInvocationChanged:         true,
		ExactReplayAfterRestart:          "passed",
		CachedEnvelopeIdentical:          true,
		ConflictingReplayAfterRestart:    "passed",
		PostAcceptanceHealth:             "passed",
		ReplayDatabase:                   "/var/lib/wardveil-scan/replay.sqlite3",
		ReplayDatabaseMode:               "0600",
		ReplayStateDirectoryMode:         "0700",
		TransientRequestStatePrivate:     true,
		TransientRequestStateRemoved:     true,
		RawResourceContentInEvidence:     false,
		CallerSecretInEvidence:           false,
		SingleHostRestartDurability:      "passed",
		MultiHostReplayDurability:        "not_proven",
		ProductionServiceIdentity:        "not_proven_by_acceptance",
		ProductionRuntimeAcceptance:      "unaccepted",
		ProtectionClaimAuthority:         false,
		ObservedAt:                       now.Add(-time.Minute).UTC().Format(time.RFC3339Nano),
	}
}

func writeRestartEvidence(t *testing.T, evidence wardveilRestartEvidence, mode os.FileMode) string {
	t.Helper()
	raw, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	path := filepath.Join(t.TempDir(), "wardveil-replay-restart.json")
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateWardveilRestartEvidence(t *testing.T) {
	now := time.Date(2026, time.August, 31, 3, 0, 0, 0, time.UTC)
	path := writeRestartEvidence(t, validRestartEvidence(now), 0o600)
	binding, err := validateWardveilRestartEvidence(
		path,
		testWardveilRevision,
		testWardveilEndpoint,
		"goreecloud-drive",
		"scan-current",
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if binding.WardveilRevision != testWardveilRevision {
		t.Fatalf("unexpected Wardveil revision %q", binding.WardveilRevision)
	}
	if len(binding.EvidenceSHA256) != 64 {
		t.Fatalf("unexpected evidence SHA-256 %q", binding.EvidenceSHA256)
	}
	if binding.ReplayDurability != "single_host_restart_durability_passed_by_validated_wardveil_runtime_evidence" {
		t.Fatalf("unexpected replay durability %q", binding.ReplayDurability)
	}
	if binding.MultiHostReplayStatus != "not_proven" {
		t.Fatalf("unexpected multi-host replay status %q", binding.MultiHostReplayStatus)
	}
}

func TestValidateWardveilRestartEvidenceRejectsRevisionMismatch(t *testing.T) {
	now := time.Date(2026, time.August, 31, 3, 0, 0, 0, time.UTC)
	path := writeRestartEvidence(t, validRestartEvidence(now), 0o600)
	_, err := validateWardveilRestartEvidence(
		path,
		strings.Repeat("a", 40),
		testWardveilEndpoint,
		"goreecloud-drive",
		"scan-current",
		now,
	)
	if err == nil || !strings.Contains(err.Error(), "revision mismatch") {
		t.Fatalf("expected revision mismatch, got %v", err)
	}
}

func TestValidateWardveilRestartEvidenceRejectsInsecureMode(t *testing.T) {
	now := time.Date(2026, time.August, 31, 3, 0, 0, 0, time.UTC)
	path := writeRestartEvidence(t, validRestartEvidence(now), 0o644)
	_, err := validateWardveilRestartEvidence(
		path,
		testWardveilRevision,
		testWardveilEndpoint,
		"goreecloud-drive",
		"scan-current",
		now,
	)
	if err == nil || !strings.Contains(err.Error(), "mode 0600") {
		t.Fatalf("expected private-mode failure, got %v", err)
	}
}

func TestValidateWardveilRestartEvidenceRejectsClaimExpansion(t *testing.T) {
	now := time.Date(2026, time.August, 31, 3, 0, 0, 0, time.UTC)
	evidence := validRestartEvidence(now)
	evidence.MultiHostReplayDurability = "passed"
	path := writeRestartEvidence(t, evidence, 0o600)
	_, err := validateWardveilRestartEvidence(
		path,
		testWardveilRevision,
		testWardveilEndpoint,
		"goreecloud-drive",
		"scan-current",
		now,
	)
	if err == nil || !strings.Contains(err.Error(), "multi-host") {
		t.Fatalf("expected multi-host claim failure, got %v", err)
	}
}

func TestValidateWardveilRestartEvidenceRejectsStaleEvidence(t *testing.T) {
	now := time.Date(2026, time.August, 31, 3, 0, 0, 0, time.UTC)
	evidence := validRestartEvidence(now)
	evidence.ObservedAt = now.Add(-25 * time.Hour).Format(time.RFC3339Nano)
	path := writeRestartEvidence(t, evidence, 0o600)
	_, err := validateWardveilRestartEvidence(
		path,
		testWardveilRevision,
		testWardveilEndpoint,
		"goreecloud-drive",
		"scan-current",
		now,
	)
	if err == nil || !strings.Contains(err.Error(), "24-hour") {
		t.Fatalf("expected stale evidence failure, got %v", err)
	}
}
