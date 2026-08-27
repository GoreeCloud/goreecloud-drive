package wardveil

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"time"
)

var testNow = time.Date(2026, 8, 27, 8, 0, 0, 0, time.UTC)

func testResource() FileResource {
	body := []byte("drive payload")
	sum := sha256.Sum256(body)
	return FileResource{
		SpaceID:      "11111111-1111-4111-8111-111111111111",
		NodeID:       "22222222-2222-4222-8222-222222222222",
		DigestSHA256: hex.EncodeToString(sum[:]),
		SizeBytes:    int64(len(body)),
	}
}

func testEnvelope(resource FileResource, result Result) ScanEnvelope {
	return ScanEnvelope{
		ResourceID:           resource.ResourceID(),
		ResourceDigestSHA256: resource.DigestSHA256,
		ScanRecord: ScanRecord{
			ContractVersion: RuntimeContractVersion,
			RecordID:        "scan-1",
			RecordType:      ScanRecordType,
			Producer:        Producer{ID: "wardveil-scan", Authoritative: true},
			Scope:           Scope{ResourceType: DriveFileResourceType, ResourceID: resource.ResourceID()},
			ObservedAt:      testNow.Add(-time.Minute),
			ValidUntil:      testNow.Add(time.Hour),
			Result:          result,
			EvidenceRefs:    []string{"evidence:scan-1"},
		},
	}
}

func TestEvaluateCleanAllowsRelease(t *testing.T) {
	resource := testResource()
	decision := Evaluate(resource, ActionDownload, testEnvelope(resource, ResultClean), testNow)
	if !decision.CanRelease || decision.Disposition != DispositionAllow {
		t.Fatalf("decision=%+v", decision)
	}
}

func TestEvaluateExpiredCleanFailsClosed(t *testing.T) {
	resource := testResource()
	envelope := testEnvelope(resource, ResultClean)
	envelope.ScanRecord.ValidUntil = testNow.Add(-time.Second)
	decision := Evaluate(resource, ActionOpen, envelope, testNow)
	if decision.CanRelease || decision.Disposition != DispositionBlockedUnverified {
		t.Fatalf("decision=%+v", decision)
	}
}

func TestEvaluateCleanRequiresEvidenceReference(t *testing.T) {
	resource := testResource()
	envelope := testEnvelope(resource, ResultClean)
	envelope.ScanRecord.EvidenceRefs = nil
	decision := Evaluate(resource, ActionShare, envelope, testNow)
	if decision.CanRelease || decision.ReasonCodes[0] != "wardveil_clean_evidence_missing" {
		t.Fatalf("decision=%+v", decision)
	}
}

func TestEvaluateMaliciousRequiresQuarantine(t *testing.T) {
	resource := testResource()
	decision := Evaluate(resource, ActionDownload, testEnvelope(resource, ResultMalicious), testNow)
	if decision.CanRelease || !decision.QuarantineRequired || decision.Disposition != DispositionBlockQuarantine {
		t.Fatalf("decision=%+v", decision)
	}
	handoff, ok := decision.QuarantineHandoff(resource)
	if !ok || !handoff.RequiresExplicitExecutorAuthority || handoff.DestructiveAction {
		t.Fatalf("handoff=%+v ok=%v", handoff, ok)
	}
}

func TestEvaluateExpiredMaliciousDigestStaysBlocking(t *testing.T) {
	resource := testResource()
	envelope := testEnvelope(resource, ResultMalicious)
	envelope.ScanRecord.ObservedAt = testNow.Add(-48 * time.Hour)
	envelope.ScanRecord.ValidUntil = testNow.Add(-24 * time.Hour)
	decision := Evaluate(resource, ActionRestoreRelease, envelope, testNow)
	if decision.Disposition != DispositionBlockQuarantine || !decision.QuarantineRequired {
		t.Fatalf("decision=%+v", decision)
	}
}

func TestEvaluateSuspiciousHoldsReview(t *testing.T) {
	resource := testResource()
	decision := Evaluate(resource, ActionUploadFinalize, testEnvelope(resource, ResultSuspicious), testNow)
	if decision.CanRelease || decision.QuarantineRequired || decision.Disposition != DispositionHoldReview {
		t.Fatalf("decision=%+v", decision)
	}
}

func TestEvaluateUnknownAndUnsupportedFailClosed(t *testing.T) {
	resource := testResource()
	for _, result := range []Result{ResultUnknown, ResultUnsupported} {
		decision := Evaluate(resource, ActionDownload, testEnvelope(resource, result), testNow)
		if decision.CanRelease || decision.Disposition != DispositionBlockedUnverified {
			t.Fatalf("result=%s decision=%+v", result, decision)
		}
	}
}

func TestEvaluateDigestMismatchFailsClosed(t *testing.T) {
	resource := testResource()
	envelope := testEnvelope(resource, ResultClean)
	envelope.ResourceDigestSHA256 = string(make([]byte, 64))
	decision := Evaluate(resource, ActionDownload, envelope, testNow)
	if decision.CanRelease || decision.ReasonCodes[0] != "wardveil_digest_mismatch" {
		t.Fatalf("decision=%+v", decision)
	}
}

func TestEvaluateScopeMismatchFailsClosed(t *testing.T) {
	resource := testResource()
	envelope := testEnvelope(resource, ResultClean)
	envelope.ScanRecord.Scope.ResourceID = "drive:other:file:other"
	decision := Evaluate(resource, ActionDownload, envelope, testNow)
	if decision.CanRelease || decision.ReasonCodes[0] != "wardveil_scope_mismatch" {
		t.Fatalf("decision=%+v", decision)
	}
}

func TestEvaluateNonAuthoritativeRecordFailsClosed(t *testing.T) {
	resource := testResource()
	envelope := testEnvelope(resource, ResultClean)
	envelope.ScanRecord.Producer.Authoritative = false
	decision := Evaluate(resource, ActionDownload, envelope, testNow)
	if decision.CanRelease || decision.ReasonCodes[0] != "wardveil_producer_not_authoritative" {
		t.Fatalf("decision=%+v", decision)
	}
}

type memoryStaging struct {
	content []byte
	opens   int
	mutate  bool
}

func (s *memoryStaging) OpenStaging(_, _ string) (io.ReadCloser, error) {
	s.opens++
	if s.mutate && s.opens >= 3 {
		return io.NopCloser(bytes.NewReader([]byte("changed payload"))), nil
	}
	return io.NopCloser(bytes.NewReader(s.content)), nil
}

type fakeScanner struct {
	result Result
	err    error
}

func (s fakeScanner) Scan(_ context.Context, request ScanRequest, body io.Reader) (ScanEnvelope, error) {
	if s.err != nil {
		return ScanEnvelope{}, s.err
	}
	content, err := io.ReadAll(body)
	if err != nil {
		return ScanEnvelope{}, err
	}
	sum := sha256.Sum256(content)
	resource := FileResource{
		SpaceID:      "11111111-1111-4111-8111-111111111111",
		NodeID:       "22222222-2222-4222-8222-222222222222",
		DigestSHA256: hex.EncodeToString(sum[:]),
		SizeBytes:    int64(len(content)),
	}
	envelope := testEnvelope(resource, s.result)
	envelope.ResourceID = request.ResourceID
	envelope.ResourceDigestSHA256 = request.DigestSHA256
	envelope.ScanRecord.Scope.ResourceID = request.ResourceID
	return envelope, nil
}

func TestStagedFileGateAllowsCurrentClean(t *testing.T) {
	store := &memoryStaging{content: []byte("drive payload")}
	gate := StagedFileGate{Store: store, Scanner: fakeScanner{result: ResultClean}, Now: func() time.Time { return testNow }}
	decision, err := gate.EvaluateUpload(context.Background(), "11111111-1111-4111-8111-111111111111", "33333333-3333-4333-8333-333333333333", "22222222-2222-4222-8222-222222222222")
	if err != nil || !decision.CanRelease {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
}

func TestStagedFileGateDetectsContentChange(t *testing.T) {
	store := &memoryStaging{content: []byte("drive payload"), mutate: true}
	gate := StagedFileGate{Store: store, Scanner: fakeScanner{result: ResultClean}, Now: func() time.Time { return testNow }}
	decision, err := gate.EvaluateUpload(context.Background(), "11111111-1111-4111-8111-111111111111", "33333333-3333-4333-8333-333333333333", "22222222-2222-4222-8222-222222222222")
	if err != nil || decision.CanRelease || decision.ReasonCodes[0] != "drive_content_changed_during_scan" {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
}

func TestStagedFileGateScannerFailureFailsClosed(t *testing.T) {
	gate := StagedFileGate{Store: &memoryStaging{content: []byte("drive payload")}, Scanner: fakeScanner{err: errors.New("offline")}}
	if _, err := gate.EvaluateUpload(context.Background(), "11111111-1111-4111-8111-111111111111", "33333333-3333-4333-8333-333333333333", "22222222-2222-4222-8222-222222222222"); err == nil {
		t.Fatal("expected scanner failure")
	}
}
