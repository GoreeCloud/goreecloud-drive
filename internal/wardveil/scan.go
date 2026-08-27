package wardveil

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	RuntimeContractVersion = "0.1.0"
	ScanRecordType         = "scan_finding"
	DriveFileResourceType  = "drive_file"
)

type Action string

const (
	ActionUploadFinalize Action = "upload_finalize"
	ActionOpen           Action = "open"
	ActionDownload       Action = "download"
	ActionShare          Action = "share"
	ActionRestoreRelease Action = "restore_release"
)

type Result string

const (
	ResultClean       Result = "clean"
	ResultSuspicious  Result = "suspicious"
	ResultMalicious   Result = "malicious"
	ResultUnknown     Result = "unknown"
	ResultUnsupported Result = "unsupported"
)

type Disposition string

const (
	DispositionAllow             Disposition = "allow"
	DispositionHoldReview        Disposition = "hold_review"
	DispositionBlockQuarantine   Disposition = "block_quarantine"
	DispositionBlockedUnverified Disposition = "blocked_unverified"
)

type Producer struct {
	ID            string `json:"id"`
	Authoritative bool   `json:"authoritative"`
}

type Scope struct {
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
}

type ScanRecord struct {
	ContractVersion string    `json:"contract_version"`
	RecordID        string    `json:"record_id"`
	RecordType      string    `json:"record_type"`
	Producer        Producer  `json:"producer"`
	Scope           Scope     `json:"scope"`
	ObservedAt      time.Time `json:"observed_at"`
	ValidUntil      time.Time `json:"valid_until"`
	Result          Result    `json:"result"`
	EvidenceRefs    []string  `json:"evidence_refs"`
}

type ScanEnvelope struct {
	ResourceID           string     `json:"resource_id"`
	ResourceDigestSHA256 string     `json:"resource_digest_sha256"`
	ScanRecord           ScanRecord `json:"scan_record"`
}

type FileResource struct {
	SpaceID      string
	NodeID       string
	DigestSHA256 string
	SizeBytes    int64
}

func (r FileResource) ResourceID() string {
	return "drive:" + r.SpaceID + ":file:" + r.NodeID
}

type ScanRequest struct {
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	DigestSHA256 string `json:"digest_sha256"`
	SizeBytes    int64  `json:"size_bytes"`
	Action       Action `json:"action"`
}

type Scanner interface {
	Scan(context.Context, ScanRequest, io.Reader) (ScanEnvelope, error)
}

type StagingReader interface {
	OpenStaging(spaceID, uploadID string) (io.ReadCloser, error)
}

type Decision struct {
	Action             Action      `json:"action"`
	Disposition        Disposition `json:"disposition"`
	CanRelease         bool        `json:"can_release"`
	QuarantineRequired bool        `json:"quarantine_required"`
	ReasonCodes        []string    `json:"reason_codes"`
	EvidenceRefs       []string    `json:"evidence_refs"`
	ScanRecordID       string      `json:"scan_record_id,omitempty"`
}

type QuarantineHandoff struct {
	ResourceType                      string   `json:"resource_type"`
	ResourceID                        string   `json:"resource_id"`
	DigestSHA256                      string   `json:"digest_sha256"`
	EvidenceRefs                      []string `json:"evidence_refs"`
	ScanRecordID                      string   `json:"scan_record_id,omitempty"`
	RequiresExplicitExecutorAuthority bool     `json:"requires_explicit_executor_authority"`
	DestructiveAction                 bool     `json:"destructive_action"`
}

func (d Decision) QuarantineHandoff(resource FileResource) (QuarantineHandoff, bool) {
	if !d.QuarantineRequired {
		return QuarantineHandoff{}, false
	}
	return QuarantineHandoff{
		ResourceType:                      DriveFileResourceType,
		ResourceID:                        resource.ResourceID(),
		DigestSHA256:                      resource.DigestSHA256,
		EvidenceRefs:                      append([]string(nil), d.EvidenceRefs...),
		ScanRecordID:                      d.ScanRecordID,
		RequiresExplicitExecutorAuthority: true,
		DestructiveAction:                 false,
	}, true
}

func Evaluate(resource FileResource, action Action, envelope ScanEnvelope, now time.Time) Decision {
	block := func(reason string) Decision {
		return Decision{Action: action, Disposition: DispositionBlockedUnverified, ReasonCodes: []string{reason}}
	}

	if resource.SpaceID == "" || resource.NodeID == "" || resource.SizeBytes < 0 || !validSHA256(resource.DigestSHA256) {
		return block("drive_resource_invalid")
	}
	if !validAction(action) {
		return block("drive_action_invalid")
	}
	if envelope.ResourceID != resource.ResourceID() {
		return block("wardveil_resource_id_mismatch")
	}
	if !strings.EqualFold(envelope.ResourceDigestSHA256, resource.DigestSHA256) {
		return block("wardveil_digest_mismatch")
	}
	record := envelope.ScanRecord
	if record.ContractVersion != RuntimeContractVersion {
		return block("wardveil_contract_version_mismatch")
	}
	if record.RecordType != ScanRecordType {
		return block("wardveil_record_type_invalid")
	}
	if !record.Producer.Authoritative || strings.TrimSpace(record.Producer.ID) == "" {
		return block("wardveil_producer_not_authoritative")
	}
	if record.Scope.ResourceType != DriveFileResourceType || record.Scope.ResourceID != resource.ResourceID() {
		return block("wardveil_scope_mismatch")
	}
	if record.ObservedAt.IsZero() || record.ValidUntil.IsZero() || record.ValidUntil.Before(record.ObservedAt) {
		return block("wardveil_evidence_window_invalid")
	}
	now = now.UTC()
	if record.ObservedAt.After(now) {
		return block("wardveil_evidence_future_dated")
	}

	if record.Result == ResultMalicious {
		return Decision{
			Action:             action,
			Disposition:        DispositionBlockQuarantine,
			QuarantineRequired: true,
			ReasonCodes:        []string{"wardveil_malicious_digest_match"},
			EvidenceRefs:       append([]string(nil), record.EvidenceRefs...),
			ScanRecordID:       record.RecordID,
		}
	}

	if now.After(record.ValidUntil.UTC()) {
		return block("wardveil_evidence_expired")
	}

	switch record.Result {
	case ResultClean:
		if len(record.EvidenceRefs) == 0 {
			return block("wardveil_clean_evidence_missing")
		}
		return Decision{
			Action:       action,
			Disposition:  DispositionAllow,
			CanRelease:   true,
			ReasonCodes:  []string{"wardveil_clean_current"},
			EvidenceRefs: append([]string(nil), record.EvidenceRefs...),
			ScanRecordID: record.RecordID,
		}
	case ResultSuspicious:
		return Decision{
			Action:       action,
			Disposition:  DispositionHoldReview,
			ReasonCodes:  []string{"wardveil_suspicious_review_required"},
			EvidenceRefs: append([]string(nil), record.EvidenceRefs...),
			ScanRecordID: record.RecordID,
		}
	case ResultUnknown:
		return block("wardveil_result_unknown")
	case ResultUnsupported:
		return block("wardveil_result_unsupported")
	default:
		return block("wardveil_result_invalid")
	}
}

type StagedFileGate struct {
	Store   StagingReader
	Scanner Scanner
	Now     func() time.Time
}

func (g StagedFileGate) EvaluateUpload(ctx context.Context, spaceID, uploadID, nodeID string) (Decision, error) {
	if g.Store == nil || g.Scanner == nil {
		return Decision{}, fmt.Errorf("Wardveil scan gate unavailable")
	}
	now := time.Now
	if g.Now != nil {
		now = g.Now
	}

	digest, size, err := hashStaging(g.Store, spaceID, uploadID)
	if err != nil {
		return Decision{}, fmt.Errorf("hash staged Drive file: %w", err)
	}
	resource := FileResource{SpaceID: spaceID, NodeID: nodeID, DigestSHA256: digest, SizeBytes: size}

	content, err := g.Store.OpenStaging(spaceID, uploadID)
	if err != nil {
		return Decision{}, fmt.Errorf("open staged Drive file for Wardveil Scan: %w", err)
	}
	envelope, scanErr := g.Scanner.Scan(ctx, ScanRequest{
		ResourceType: DriveFileResourceType,
		ResourceID:   resource.ResourceID(),
		DigestSHA256: digest,
		SizeBytes:    size,
		Action:       ActionUploadFinalize,
	}, content)
	closeErr := content.Close()
	if scanErr != nil {
		return Decision{}, fmt.Errorf("Wardveil Scan failed: %w", scanErr)
	}
	if closeErr != nil {
		return Decision{}, fmt.Errorf("close staged Drive file after Wardveil Scan: %w", closeErr)
	}

	decision := Evaluate(resource, ActionUploadFinalize, envelope, now().UTC())
	if !decision.CanRelease {
		return decision, nil
	}

	afterDigest, afterSize, err := hashStaging(g.Store, spaceID, uploadID)
	if err != nil {
		return Decision{}, fmt.Errorf("rehash staged Drive file after Wardveil Scan: %w", err)
	}
	if afterSize != size || !strings.EqualFold(afterDigest, digest) {
		return Decision{
			Action:      ActionUploadFinalize,
			Disposition: DispositionBlockedUnverified,
			ReasonCodes: []string{"drive_content_changed_during_scan"},
		}, nil
	}
	return decision, nil
}

func hashStaging(store StagingReader, spaceID, uploadID string) (string, int64, error) {
	content, err := store.OpenStaging(spaceID, uploadID)
	if err != nil {
		return "", 0, err
	}
	hash := sha256.New()
	size, copyErr := io.Copy(hash, content)
	closeErr := content.Close()
	if copyErr != nil {
		return "", 0, copyErr
	}
	if closeErr != nil {
		return "", 0, closeErr
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validAction(action Action) bool {
	switch action {
	case ActionUploadFinalize, ActionOpen, ActionDownload, ActionShare, ActionRestoreRelease:
		return true
	default:
		return false
	}
}
