package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const maxWardveilRestartEvidenceBytes = 64 << 10

type wardveilRestartEvidence struct {
	Component                         string `json:"component"`
	WardveilRevision                  string `json:"wardveil_revision"`
	WardveilEndpoint                  string `json:"wardveil_endpoint"`
	Service                           string `json:"service"`
	CallerID                          string `json:"caller_id"`
	KeyID                             string `json:"key_id"`
	ResourceType                      string `json:"resource_type"`
	InitialAuthenticatedCleanRequest  string `json:"initial_authenticated_clean_request"`
	ServiceRestart                    string `json:"service_restart"`
	SystemdInvocationChanged          bool   `json:"systemd_invocation_changed"`
	ExactReplayAfterRestart           string `json:"exact_replay_after_restart"`
	CachedEnvelopeIdentical           bool   `json:"cached_envelope_identical"`
	ConflictingReplayAfterRestart     string `json:"conflicting_replay_after_restart"`
	PostAcceptanceHealth              string `json:"post_acceptance_health"`
	ReplayDatabase                    string `json:"replay_database"`
	ReplayDatabaseMode                string `json:"replay_database_mode"`
	ReplayStateDirectoryMode          string `json:"replay_state_directory_mode"`
	TransientRequestStatePrivate      bool   `json:"transient_request_state_private"`
	TransientRequestStateRemoved      bool   `json:"transient_request_state_removed"`
	RawResourceContentInEvidence      bool   `json:"raw_resource_content_in_evidence"`
	CallerSecretInEvidence            bool   `json:"caller_secret_in_evidence"`
	SingleHostRestartDurability       string `json:"single_host_restart_durability"`
	MultiHostReplayDurability         string `json:"multi_host_replay_durability"`
	ProductionServiceIdentity         string `json:"production_service_identity"`
	ProductionRuntimeAcceptance       string `json:"production_runtime_acceptance"`
	ProtectionClaimAuthority          bool   `json:"protection_claim_authority"`
	ObservedAt                        string `json:"observed_at"`
}

type replayEvidenceBinding struct {
	WardveilRevision       string
	EvidenceSHA256         string
	ObservedAt             time.Time
	ReplayDurability       string
	MultiHostReplayStatus  string
}

func validateWardveilRestartEvidence(path, expectedRevision, expectedEndpoint, callerID, keyID string, now time.Time) (replayEvidenceBinding, error) {
	if !filepath.IsAbs(path) {
		return replayEvidenceBinding{}, errors.New("Wardveil restart evidence path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return replayEvidenceBinding{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return replayEvidenceBinding{}, errors.New("Wardveil restart evidence must be a regular non-symlink file")
	}
	if info.Mode().Perm() != 0o600 {
		return replayEvidenceBinding{}, fmt.Errorf("Wardveil restart evidence must be mode 0600, got %04o", info.Mode().Perm())
	}
	if info.Size() <= 0 || info.Size() > maxWardveilRestartEvidenceBytes {
		return replayEvidenceBinding{}, fmt.Errorf("Wardveil restart evidence size is outside the accepted bound: %d", info.Size())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return replayEvidenceBinding{}, err
	}
	if len(raw) > maxWardveilRestartEvidenceBytes {
		return replayEvidenceBinding{}, errors.New("Wardveil restart evidence exceeds the accepted bound")
	}
	var evidence wardveilRestartEvidence
	if err := json.Unmarshal(raw, &evidence); err != nil {
		return replayEvidenceBinding{}, fmt.Errorf("decode Wardveil restart evidence: %w", err)
	}
	if evidence.Component != "Wardveil Scan durable same-host replay restart acceptance" {
		return replayEvidenceBinding{}, errors.New("unexpected Wardveil restart evidence component")
	}
	if evidence.WardveilRevision != expectedRevision {
		return replayEvidenceBinding{}, fmt.Errorf("Wardveil restart evidence revision mismatch: got %s", evidence.WardveilRevision)
	}
	if evidence.WardveilEndpoint != expectedEndpoint {
		return replayEvidenceBinding{}, fmt.Errorf("Wardveil restart evidence endpoint mismatch: got %s", evidence.WardveilEndpoint)
	}
	if evidence.Service != "wardveil-scan.service" {
		return replayEvidenceBinding{}, errors.New("Wardveil restart evidence service mismatch")
	}
	if evidence.CallerID != callerID || evidence.KeyID != keyID || evidence.ResourceType != wardveil.DriveFileResourceType {
		return replayEvidenceBinding{}, errors.New("Wardveil restart evidence caller, key, or resource scope mismatch")
	}
	if evidence.InitialAuthenticatedCleanRequest != "passed" ||
		evidence.ServiceRestart != "passed" ||
		!evidence.SystemdInvocationChanged ||
		evidence.ExactReplayAfterRestart != "passed" ||
		!evidence.CachedEnvelopeIdentical ||
		evidence.ConflictingReplayAfterRestart != "passed" ||
		evidence.PostAcceptanceHealth != "passed" {
		return replayEvidenceBinding{}, errors.New("Wardveil restart evidence does not prove the required restart replay behavior")
	}
	if evidence.ReplayDatabase != "/var/lib/wardveil-scan/replay.sqlite3" ||
		evidence.ReplayDatabaseMode != "0600" ||
		evidence.ReplayStateDirectoryMode != "0700" {
		return replayEvidenceBinding{}, errors.New("Wardveil restart evidence does not prove the accepted private replay-state contract")
	}
	if !evidence.TransientRequestStatePrivate || !evidence.TransientRequestStateRemoved ||
		evidence.RawResourceContentInEvidence || evidence.CallerSecretInEvidence {
		return replayEvidenceBinding{}, errors.New("Wardveil restart evidence violates the accepted transient-state or evidence-minimization contract")
	}
	if evidence.SingleHostRestartDurability != "passed" {
		return replayEvidenceBinding{}, errors.New("Wardveil restart evidence does not prove single-host restart durability")
	}
	if evidence.MultiHostReplayDurability != "not_proven" {
		return replayEvidenceBinding{}, errors.New("Wardveil restart evidence unexpectedly claims multi-host replay durability")
	}
	if evidence.ProductionServiceIdentity != "not_proven_by_acceptance" ||
		evidence.ProductionRuntimeAcceptance != "unaccepted" ||
		evidence.ProtectionClaimAuthority {
		return replayEvidenceBinding{}, errors.New("Wardveil restart evidence exceeds the accepted production claim boundary")
	}
	observedAt, err := time.Parse(time.RFC3339Nano, evidence.ObservedAt)
	if err != nil {
		return replayEvidenceBinding{}, fmt.Errorf("parse Wardveil restart evidence observation time: %w", err)
	}
	if observedAt.After(now.Add(5 * time.Minute)) {
		return replayEvidenceBinding{}, errors.New("Wardveil restart evidence observation time is unexpectedly in the future")
	}
	if now.Sub(observedAt) > 24*time.Hour {
		return replayEvidenceBinding{}, errors.New("Wardveil restart evidence is older than the 24-hour Drive revalidation window")
	}
	digest := sha256.Sum256(raw)
	return replayEvidenceBinding{
		WardveilRevision:      expectedRevision,
		EvidenceSHA256:        hex.EncodeToString(digest[:]),
		ObservedAt:            observedAt.UTC(),
		ReplayDurability:      "single_host_restart_durability_passed_by_validated_wardveil_runtime_evidence",
		MultiHostReplayStatus: "not_proven",
	}, nil
}
