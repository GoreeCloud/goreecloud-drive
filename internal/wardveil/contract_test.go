package wardveil

import (
	"encoding/json"
	"os"
	"testing"
)

func TestDriveWardveilContractMatchesConsumer(t *testing.T) {
	body, err := os.ReadFile("../../contracts/wardveil.drive-file-scan.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		ContractVersion                       string   `json:"contract_version"`
		Consumer                              string   `json:"consumer"`
		WardveilRuntimeContractVersion        string   `json:"wardveil_runtime_contract_version"`
		ResourceType                          string   `json:"resource_type"`
		DirectClamAVAccessAllowed             bool     `json:"direct_clamav_access_allowed"`
		FileDigestBindingRequired             bool     `json:"file_digest_binding_required"`
		AuthoritativeScanRecordRequired       bool     `json:"authoritative_scan_record_required"`
		CleanRequiresCurrentUnexpiredEvidence bool     `json:"clean_requires_current_unexpired_evidence"`
		CleanRequiresEvidenceRefs             bool     `json:"clean_requires_evidence_refs"`
		LifecycleActions                      []string `json:"lifecycle_actions"`
		ProductionRuntimeStatus               string   `json:"production_runtime_status"`
	}
	if err := json.Unmarshal(body, &contract); err != nil {
		t.Fatal(err)
	}
	if contract.ContractVersion != "0.1.0" || contract.Consumer != "GoreeCloud Drive" {
		t.Fatalf("unexpected consumer contract: %+v", contract)
	}
	if contract.WardveilRuntimeContractVersion != RuntimeContractVersion || contract.ResourceType != DriveFileResourceType {
		t.Fatalf("runtime/resource mismatch: %+v", contract)
	}
	if contract.DirectClamAVAccessAllowed || !contract.FileDigestBindingRequired || !contract.AuthoritativeScanRecordRequired {
		t.Fatalf("security boundary weakened: %+v", contract)
	}
	if !contract.CleanRequiresCurrentUnexpiredEvidence || !contract.CleanRequiresEvidenceRefs {
		t.Fatalf("clean evidence requirements weakened: %+v", contract)
	}
	if contract.ProductionRuntimeStatus != "unaccepted" {
		t.Fatalf("source integration must not claim production acceptance: %q", contract.ProductionRuntimeStatus)
	}
	want := map[string]bool{
		string(ActionUploadFinalize): false,
		string(ActionOpen):           false,
		string(ActionDownload):       false,
		string(ActionShare):          false,
		string(ActionRestoreRelease): false,
	}
	for _, action := range contract.LifecycleActions {
		if _, ok := want[action]; ok {
			want[action] = true
		}
	}
	for action, found := range want {
		if !found {
			t.Fatalf("contract missing lifecycle action %q", action)
		}
	}
}
