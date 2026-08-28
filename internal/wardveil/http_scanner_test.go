package wardveil

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func scanRequestFor(body []byte) ScanRequest {
	sum := sha256.Sum256(body)
	return ScanRequest{
		ResourceType: DriveFileResourceType,
		ResourceID:   "drive:space-1:file:node-1",
		DigestSHA256: hex.EncodeToString(sum[:]),
		SizeBytes:    int64(len(body)),
		Action:       ActionUploadFinalize,
	}
}

func canonicalScanResponse(request ScanRequest, result Result) string {
	return fmt.Sprintf(`{
  "resource_id": %q,
  "resource_digest_sha256": %q,
  "scan_record": {
    "contract_version": "0.1.0",
    "record_id": "scan-live-1",
    "record_type": "scan_finding",
    "correlation_id": "scan-request-1",
    "producer": {"id": "wardveil-scan-clamav", "authoritative": true},
    "scope": {"resource_type": "drive_file", "resource_id": %q},
    "observed_at": "2026-08-28T13:36:54Z",
    "valid_until": "2026-08-28T13:41:54Z",
    "evidence_refs": ["clamav:sha256:%s:clean", "wardveil:clamav-health:2026-08-28T13:36:54Z:healthy"],
    "scan_result": %q
  }
}`, request.ResourceID, request.DigestSHA256, request.ResourceID, request.DigestSHA256, result)
}

func newTestScanner(t *testing.T, handler http.HandlerFunc, maxResponse int64) *HTTPScanner {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	scanner, err := NewHTTPScanner(HTTPScannerConfig{
		Endpoint:         server.URL + WardveilScanPath,
		Token:            strings.Repeat("t", 64),
		Timeout:          2 * time.Second,
		MaxResponseBytes: maxResponse,
	})
	if err != nil {
		t.Fatalf("NewHTTPScanner: %v", err)
	}
	return scanner
}

func TestHTTPScannerSendsAuthenticatedBoundRequestAndMapsCanonicalResult(t *testing.T) {
	body := []byte("Drive staged upload acceptance sample")
	request := scanRequestFor(body)
	scanner := newTestScanner(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != WardveilScanPath {
			t.Fatalf("method=%s path=%s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+strings.Repeat("t", 64) {
			t.Fatal("missing or incorrect bearer token")
		}
		if got := r.Header.Get("Content-Type"); got != "application/octet-stream" {
			t.Fatalf("content-type=%q", got)
		}
		checks := map[string]string{
			"X-Wardveil-Resource-Type":   request.ResourceType,
			"X-Wardveil-Resource-ID":     request.ResourceID,
			"X-Wardveil-Digest-SHA256":   request.DigestSHA256,
			"X-Wardveil-Size-Bytes":      fmt.Sprintf("%d", request.SizeBytes),
			"X-Wardveil-Action":          string(request.Action),
		}
		for name, want := range checks {
			if got := r.Header.Get(name); got != want {
				t.Fatalf("%s=%q want=%q", name, got, want)
			}
		}
		gotBody, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if !bytes.Equal(gotBody, body) {
			t.Fatalf("body=%q", gotBody)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, canonicalScanResponse(request, ResultClean))
	}, defaultMaxScanResponseBytes)

	envelope, err := scanner.Scan(context.Background(), request, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if envelope.ResourceID != request.ResourceID || envelope.ResourceDigestSHA256 != request.DigestSHA256 {
		t.Fatalf("envelope=%+v", envelope)
	}
	if envelope.ScanRecord.Result != ResultClean {
		t.Fatalf("result=%q", envelope.ScanRecord.Result)
	}
	if envelope.ScanRecord.RecordType != ScanRecordType || !envelope.ScanRecord.Producer.Authoritative {
		t.Fatalf("record=%+v", envelope.ScanRecord)
	}
	if len(envelope.ScanRecord.EvidenceRefs) != 2 {
		t.Fatalf("evidence=%v", envelope.ScanRecord.EvidenceRefs)
	}
}

func TestHTTPScannerRejectsUnsafeConfiguration(t *testing.T) {
	for _, endpoint := range []string{
		"http://192.0.2.10:8791/v1/scan",
		"https://127.0.0.1:8791/v1/scan",
		"http://127.0.0.1/v1/scan",
		"http://user@127.0.0.1:8791/v1/scan",
		"http://127.0.0.1:8791/v1/scan?debug=1",
		"http://127.0.0.1:8791/other",
	} {
		if _, err := NewHTTPScanner(HTTPScannerConfig{Endpoint: endpoint, Token: strings.Repeat("t", 64)}); err == nil {
			t.Fatalf("expected endpoint rejection: %s", endpoint)
		}
	}
	if _, err := NewHTTPScanner(HTTPScannerConfig{
		Endpoint: "http://127.0.0.1:8791/v1/scan",
		Token:    "short",
	}); err == nil {
		t.Fatal("expected short token rejection")
	}
}

func TestHTTPScannerNonSuccessFailsClosed(t *testing.T) {
	body := []byte("Drive staged upload")
	request := scanRequestFor(body)
	scanner := newTestScanner(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}, defaultMaxScanResponseBytes)
	if _, err := scanner.Scan(context.Background(), request, bytes.NewReader(body)); err == nil {
		t.Fatal("expected non-success response error")
	}
}

func TestHTTPScannerRejectsUnknownWireFieldsAndOversizedResponse(t *testing.T) {
	body := []byte("Drive staged upload")
	request := scanRequestFor(body)

	unknown := newTestScanner(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"unexpected":true}`)
	}, defaultMaxScanResponseBytes)
	if _, err := unknown.Scan(context.Background(), request, bytes.NewReader(body)); err == nil {
		t.Fatal("expected unknown-field response error")
	}

	oversized := newTestScanner(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, strings.Repeat("x", 65))
	}, 64)
	if _, err := oversized.Scan(context.Background(), request, bytes.NewReader(body)); err == nil {
		t.Fatal("expected oversized response error")
	}
}

func TestHTTPScannerRejectsRedirectWithoutForwardingCredentials(t *testing.T) {
	body := []byte("Drive staged upload")
	request := scanRequestFor(body)
	redirectTargetCalled := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectTargetCalled = true
		if r.Header.Get("Authorization") != "" {
			t.Fatal("authorization forwarded across redirect")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	scanner := newTestScanner(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, target.URL+WardveilScanPath, http.StatusTemporaryRedirect)
	}, defaultMaxScanResponseBytes)
	if _, err := scanner.Scan(context.Background(), request, bytes.NewReader(body)); err == nil {
		t.Fatal("expected redirect to fail closed")
	}
	if redirectTargetCalled {
		t.Fatal("redirect target should not be called")
	}
}
