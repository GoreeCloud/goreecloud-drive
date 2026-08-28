package wardveil

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	WardveilScanPath             = "/v1/scan"
	WardveilScanContractVersion  = "0.1.0"
	defaultScanTimeout           = 35 * time.Second
	defaultMaxScanResponseBytes  = int64(1 << 20)
	minimumScanCallerSecretBytes = 32
	defaultScanCallerID          = "goreecloud-drive"
	defaultScanKeyID             = "scan-current"
)

type HTTPScannerConfig struct {
	Endpoint         string
	CallerID         string
	KeyID            string
	Secret           string
	Timeout          time.Duration
	MaxResponseBytes int64
	Now              func() time.Time
	Nonce            func() (string, error)
	CorrelationID    func() (string, error)
}

type HTTPScanner struct {
	endpoint         *url.URL
	callerID         string
	keyID            string
	secret           []byte
	client           *http.Client
	maxResponseBytes int64
	now              func() time.Time
	nonce            func() (string, error)
	correlationID    func() (string, error)
}

type scanRecordWire struct {
	ContractVersion string    `json:"contract_version"`
	RecordID        string    `json:"record_id"`
	RecordType      string    `json:"record_type"`
	CorrelationID   string    `json:"correlation_id"`
	Producer        Producer  `json:"producer"`
	Scope           Scope     `json:"scope"`
	ObservedAt      time.Time `json:"observed_at"`
	ValidUntil      time.Time `json:"valid_until"`
	Result          Result    `json:"result"`
	EvidenceRefs    []string  `json:"evidence_refs"`
}

type scanEnvelopeWire struct {
	ResourceID           string         `json:"resource_id"`
	ResourceDigestSHA256 string         `json:"resource_digest_sha256"`
	ScanRecord           scanRecordWire `json:"scan_record"`
}

func NewHTTPScanner(cfg HTTPScannerConfig) (*HTTPScanner, error) {
	endpoint, err := validateScanEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	callerID := cfg.CallerID
	if callerID == "" {
		callerID = defaultScanCallerID
	}
	keyID := cfg.KeyID
	if keyID == "" {
		keyID = defaultScanKeyID
	}
	if !validScanToken(callerID) || !validScanToken(keyID) {
		return nil, errors.New("Wardveil Scan caller or key identity invalid")
	}
	if cfg.Secret != strings.TrimSpace(cfg.Secret) || len([]byte(cfg.Secret)) < minimumScanCallerSecretBytes {
		return nil, errors.New("Wardveil Scan caller secret must be at least 32 bytes with no surrounding whitespace")
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultScanTimeout
	}
	if timeout <= 0 {
		return nil, errors.New("Wardveil Scan timeout must be positive")
	}
	maxResponseBytes := cfg.MaxResponseBytes
	if maxResponseBytes == 0 {
		maxResponseBytes = defaultMaxScanResponseBytes
	}
	if maxResponseBytes <= 0 {
		return nil, errors.New("Wardveil Scan response limit must be positive")
	}

	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	nonce := cfg.Nonce
	if nonce == nil {
		nonce = func() (string, error) { return randomScanToken("drive-nonce") }
	}
	correlationID := cfg.CorrelationID
	if correlationID == nil {
		correlationID = func() (string, error) { return randomScanToken("drive-scan") }
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &HTTPScanner{
		endpoint:         endpoint,
		callerID:         callerID,
		keyID:            keyID,
		secret:           []byte(cfg.Secret),
		client:           client,
		maxResponseBytes: maxResponseBytes,
		now:              now,
		nonce:            nonce,
		correlationID:    correlationID,
	}, nil
}

func validateScanEndpoint(raw string) (*url.URL, error) {
	endpoint, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse Wardveil Scan endpoint: %w", err)
	}
	if endpoint.Scheme != "http" {
		return nil, errors.New("Wardveil Scan endpoint must use loopback HTTP")
	}
	if endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("Wardveil Scan endpoint must not include userinfo, query, or fragment")
	}
	if endpoint.Path != WardveilScanPath {
		return nil, fmt.Errorf("Wardveil Scan endpoint path must be %s", WardveilScanPath)
	}
	if endpoint.Port() == "" {
		return nil, errors.New("Wardveil Scan endpoint must include an explicit port")
	}
	ip := net.ParseIP(endpoint.Hostname())
	if ip == nil || !ip.IsLoopback() || ip.To4() == nil {
		return nil, errors.New("Wardveil Scan endpoint must use an IPv4 loopback address")
	}
	return endpoint, nil
}

func (s *HTTPScanner) Scan(ctx context.Context, request ScanRequest, body io.Reader) (ScanEnvelope, error) {
	if s == nil || s.endpoint == nil || s.client == nil || s.now == nil || s.nonce == nil || s.correlationID == nil {
		return ScanEnvelope{}, errors.New("Wardveil Scan HTTP client unavailable")
	}
	if body == nil {
		return ScanEnvelope{}, errors.New("Wardveil Scan body unavailable")
	}
	if request.ResourceType != DriveFileResourceType || strings.TrimSpace(request.ResourceID) == "" {
		return ScanEnvelope{}, errors.New("Wardveil Scan resource identity invalid")
	}
	if !validSHA256(request.DigestSHA256) || request.SizeBytes < 0 || !validAction(request.Action) {
		return ScanEnvelope{}, errors.New("Wardveil Scan request metadata invalid")
	}

	timestamp := s.now().UTC().Format(time.RFC3339Nano)
	nonce, err := s.nonce()
	if err != nil || !validScanToken(nonce) {
		return ScanEnvelope{}, errors.New("generate Wardveil Scan nonce")
	}
	correlationID, err := s.correlationID()
	if err != nil || !validScanToken(correlationID) {
		return ScanEnvelope{}, errors.New("generate Wardveil Scan correlation ID")
	}
	digest := strings.ToLower(request.DigestSHA256)
	signature := signScanRequest(
		s.secret,
		s.callerID,
		s.keyID,
		timestamp,
		nonce,
		string(request.Action),
		request.ResourceType,
		request.ResourceID,
		correlationID,
		request.SizeBytes,
		digest,
	)

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint.String(), body)
	if err != nil {
		return ScanEnvelope{}, fmt.Errorf("create Wardveil Scan request: %w", err)
	}
	httpRequest.ContentLength = request.SizeBytes
	httpRequest.Header.Set("Content-Type", "application/octet-stream")
	httpRequest.Header.Set("X-Wardveil-Caller-ID", s.callerID)
	httpRequest.Header.Set("X-Wardveil-Key-ID", s.keyID)
	httpRequest.Header.Set("X-Wardveil-Timestamp", timestamp)
	httpRequest.Header.Set("X-Wardveil-Nonce", nonce)
	httpRequest.Header.Set("X-Wardveil-Resource-Type", request.ResourceType)
	httpRequest.Header.Set("X-Wardveil-Resource-ID", request.ResourceID)
	httpRequest.Header.Set("X-Wardveil-Digest-SHA256", digest)
	httpRequest.Header.Set("X-Wardveil-Size-Bytes", strconv.FormatInt(request.SizeBytes, 10))
	httpRequest.Header.Set("X-Wardveil-Action", string(request.Action))
	httpRequest.Header.Set("X-Wardveil-Correlation-ID", correlationID)
	httpRequest.Header.Set("X-Wardveil-Signature", signature)

	response, err := s.client.Do(httpRequest)
	if err != nil {
		return ScanEnvelope{}, fmt.Errorf("execute Wardveil Scan request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ScanEnvelope{}, fmt.Errorf("Wardveil Scan returned HTTP %d", response.StatusCode)
	}
	if contentType := response.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		return ScanEnvelope{}, errors.New("Wardveil Scan response content type invalid")
	}

	limited := io.LimitReader(response.Body, s.maxResponseBytes+1)
	encoded, err := io.ReadAll(limited)
	if err != nil {
		return ScanEnvelope{}, fmt.Errorf("read Wardveil Scan response: %w", err)
	}
	if int64(len(encoded)) > s.maxResponseBytes {
		return ScanEnvelope{}, errors.New("Wardveil Scan response exceeds configured limit")
	}

	var wire scanEnvelopeWire
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return ScanEnvelope{}, fmt.Errorf("decode Wardveil Scan response: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return ScanEnvelope{}, err
	}
	if wire.ScanRecord.CorrelationID != correlationID {
		return ScanEnvelope{}, errors.New("Wardveil Scan response correlation mismatch")
	}

	return ScanEnvelope{
		ResourceID:           wire.ResourceID,
		ResourceDigestSHA256: wire.ResourceDigestSHA256,
		ScanRecord: ScanRecord{
			ContractVersion: wire.ScanRecord.ContractVersion,
			RecordID:        wire.ScanRecord.RecordID,
			RecordType:      wire.ScanRecord.RecordType,
			Producer:        wire.ScanRecord.Producer,
			Scope:           wire.ScanRecord.Scope,
			ObservedAt:      wire.ScanRecord.ObservedAt,
			ValidUntil:      wire.ScanRecord.ValidUntil,
			Result:          wire.ScanRecord.Result,
			EvidenceRefs:    append([]string(nil), wire.ScanRecord.EvidenceRefs...),
		},
	}, nil
}

func signScanRequest(
	secret []byte,
	callerID, keyID, timestamp, nonce, action, resourceType, resourceID, correlationID string,
	sizeBytes int64,
	digestSHA256 string,
) string {
	material := strings.Join([]string{
		WardveilScanContractVersion,
		callerID,
		keyID,
		timestamp,
		nonce,
		action,
		resourceType,
		resourceID,
		correlationID,
		strconv.FormatInt(sizeBytes, 10),
		digestSHA256,
	}, "\n")
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(material))
	return hex.EncodeToString(mac.Sum(nil))
}

func randomScanToken(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(raw[:]), nil
}

func validScanToken(value string) bool {
	if len(value) < 1 || len(value) > 256 {
		return false
	}
	for i, char := range value {
		if (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '.' || char == '_' || char == ':' || char == '-' {
			if i == 0 && !((char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9')) {
				return false
			}
			continue
		}
		return false
	}
	return true
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode trailing Wardveil Scan response: %w", err)
	}
	return errors.New("Wardveil Scan response contains multiple JSON values")
}
