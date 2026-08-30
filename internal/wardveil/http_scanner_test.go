package wardveil

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

var fixedHTTPScanTime = time.Date(2026, 8, 28, 19, 30, 0, 0, time.UTC)

const testCallerID = "goreecloud-drive"
const testKeyID = "scan-current"

var testCallerSecret = strings.Repeat("s", 64)

type closeTrackingReader struct {
	*bytes.Reader
	closed bool
}

func (r *closeTrackingReader) Close() error {
	r.closed = true
	return nil
}

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

func canonicalScanResponse(request ScanRequest, correlationID string, result Result) string {
	return fmt.Sprintf(`{
  "resource_id": %q,
  "resource_digest_sha256": %q,
  "scan_record": {
    "contract_version": "0.1.0",
    "record_id": "scan-live-1",
    "record_type": "scan_finding",
    "correlation_id": %q,
    "producer": {"id": "wardveil-scan-clamav", "authoritative": true},
    "scope": {"resource_type": "drive_file", "resource_id": %q},
    "observed_at": "2026-08-28T19:30:00Z",
    "valid_until": "2026-08-28T19:35:00Z",
    "result": %q,
    "evidence_refs": ["clamav:sha256:%s:clean", "wardveil:clamav-health:2026-08-28T19:30:00Z:healthy"]
  }
}`, request.ResourceID, request.DigestSHA256, correlationID, request.ResourceID, result, request.DigestSHA256)
}

func newTestScanner(t *testing.T, handler http.HandlerFunc, maxResponse int64) *HTTPScanner {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	scanner, err := NewHTTPScanner(HTTPScannerConfig{
		Endpoint:         server.URL + WardveilScanPath,
		CallerID:         testCallerID,
		KeyID:            testKeyID,
		Secret:           testCallerSecret,
		Timeout:          2 * time.Second,
		MaxResponseBytes: maxResponse,
		Now:              func() time.Time { return fixedHTTPScanTime },
		Nonce:            func() (string, error) { return "drive-nonce-fixed", nil },
		CorrelationID:    func() (string, error) { return "drive-scan-fixed", nil },
	})
	if err != nil {
		t.Fatalf("NewHTTPScanner: %v", err)
	}
	return scanner
}

func TestHTTPScannerSendsSignedBoundRequestAndMapsConsumerResult(t *testing.T) {
	body := []byte("Drive staged upload acceptance sample")
	request := scanRequestFor(body)
	scanner := newTestScanner(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != WardveilScanPath {
			t.Fatalf("method=%s path=%s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("unexpected bearer authorization=%q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/octet-stream" {
			t.Fatalf("content-type=%q", got)
		}
		timestamp := fixedHTTPScanTime.Format(time.RFC3339Nano)
		checks := map[string]string{
			"X-Wardveil-Caller-ID":      testCallerID,
			"X-Wardveil-Key-ID":         testKeyID,
			"X-Wardveil-Timestamp":      timestamp,
			"X-Wardveil-Nonce":          "drive-nonce-fixed",
			"X-Wardveil-Resource-Type":  request.ResourceType,
			"X-Wardveil-Resource-ID":    request.ResourceID,
			"X-Wardveil-Digest-SHA256":  request.DigestSHA256,
			"X-Wardveil-Size-Bytes":     strconv.FormatInt(request.SizeBytes, 10),
			"X-Wardveil-Action":         string(request.Action),
			"X-Wardveil-Correlation-ID": "drive-scan-fixed",
		}
		for name, want := range checks {
			if got := r.Header.Get(name); got != want {
				t.Fatalf("%s=%q want=%q", name, got, want)
			}
		}
		material := strings.Join([]string{
			WardveilScanContractVersion,
			testCallerID,
			testKeyID,
			timestamp,
			"drive-nonce-fixed",
			string(request.Action),
			request.ResourceType,
			request.ResourceID,
			"drive-scan-fixed",
			strconv.FormatInt(request.SizeBytes, 10),
			request.DigestSHA256,
		}, "\n")
		mac := hmac.New(sha256.New, []byte(testCallerSecret))
		_, _ = mac.Write([]byte(material))
		wantSignature := hex.EncodeToString(mac.Sum(nil))
		if got := r.Header.Get("X-Wardveil-Signature"); got != wantSignature {
			t.Fatalf("signature=%q want=%q", got, wantSignature)
		}
		gotBody, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if !bytes.Equal(gotBody, body) {
			t.Fatalf("body=%q", gotBody)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, canonicalScanResponse(request, "drive-scan-fixed", ResultClean))
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

func TestHTTPScannerDoesNotCloseCallerOwnedBody(t *testing.T) {
	body := []byte("Drive staged upload body ownership")
	request := scanRequestFor(body)
	reader := &closeTrackingReader{Reader: bytes.NewReader(body)}
	scanner := newTestScanner(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, canonicalScanResponse(request, "drive-scan-fixed", ResultClean))
	}, defaultMaxScanResponseBytes)

	if _, err := scanner.Scan(context.Background(), request, reader); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if reader.closed {
		t.Fatal("HTTPScanner closed caller-owned request body")
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("caller close: %v", err)
	}
	if !reader.closed {
		t.Fatal("caller-owned body should close when caller closes it")
	}
}

func TestHTTPScannerRejectsUnsafeConfiguration(t *testing.T) {
	base := HTTPScannerConfig{CallerID: testCallerID, KeyID: testKeyID, Secret: testCallerSecret}
	for _, endpoint := range []string{
		"http://192.0.2.10:8791/v1/scan",
		"https://127.0.0.1:8791/v1/scan",
		"http://127.0.0.1/v1/scan",
		"http://user@127.0.0.1:8791/v1/scan",
		"http://127.0.0.1:8791/v1/scan?debug=1",
		"http://127.0.0.1:8791/other",
	} {
		cfg := base
		cfg.Endpoint = endpoint
		if _, err := NewHTTPScanner(cfg); err == nil {
			t.Fatalf("expected endpoint rejection: %s", endpoint)
		}
	}
	if _, err := NewHTTPScanner(HTTPScannerConfig{
		Endpoint: "http://127.0.0.1:8791/v1/scan",
		CallerID: "bad caller",
		KeyID:    testKeyID,
		Secret:   testCallerSecret,
	}); err == nil {
		t.Fatal("expected caller identity rejection")
	}
	if _, err := NewHTTPScanner(HTTPScannerConfig{
		Endpoint: "http://127.0.0.1:8791/v1/scan",
		CallerID: testCallerID,
		KeyID:    testKeyID,
		Secret:   "short",
	}); err == nil {
		t.Fatal("expected short secret rejection")
	}
}

func TestHTTPScannerNonSuccessFailsClosed(t *testing.T) {
	body := []byte("Drive staged upload")
	request := scanRequestFor(body)
	scanner := newTestScanner(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rejected", http.StatusUnauthorized)
	}, defaultMaxScanResponseBytes)
	if _, err := scanner.Scan(context.Background(), request, bytes.NewReader(body)); err == nil {
		t.Fatal("expected non-success response error")
	}
}

func TestHTTPScannerRejectsUnknownWireFieldsOversizeAndCorrelationMismatch(t *testing.T) {
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

	mismatch := newTestScanner(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, canonicalScanResponse(request, "other-correlation", ResultClean))
	}, defaultMaxScanResponseBytes)
	if _, err := mismatch.Scan(context.Background(), request, bytes.NewReader(body)); err == nil {
		t.Fatal("expected correlation mismatch error")
	}
}

func TestHTTPScannerRejectsRedirectWithoutCallingTarget(t *testing.T) {
	body := []byte("Drive staged upload")
	request := scanRequestFor(body)
	redirectTargetCalled := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectTargetCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	scanner := newTestScanner(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+WardveilScanPath, http.StatusTemporaryRedirect)
	}, defaultMaxScanResponseBytes)
	if _, err := scanner.Scan(context.Background(), request, bytes.NewReader(body)); err == nil {
		t.Fatal("expected redirect to fail closed")
	}
	if redirectTargetCalled {
		t.Fatal("redirect target should not be called")
	}
}
