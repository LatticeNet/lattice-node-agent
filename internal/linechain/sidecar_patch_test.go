package linechain

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	sourceUUID = "11111111-1111-4111-8111-1111111111aa"
	oldUUID    = "22222222-2222-4222-8222-222222222222"
	newUUID    = "33333333-3333-4333-8333-333333333333"
	otherUUID  = "44444444-4444-4444-8444-444444444444"
)

func stringPtr(value string) *string { return &value }

func patchBytes(expected, desired *string) []byte {
	b, err := json.Marshal(semanticSidecarPatchV2{Schema: semanticSidecarSchema, SourceLineUUID: sourceUUID, SourceInboundTag: "source", ExpectedDownstreamLineUUID: expected, DesiredDownstreamLineUUID: desired})
	if err != nil {
		panic(err)
	}
	return b
}

func TestCanonicalSemanticSidecarPatchRequiresExactShape(t *testing.T) {
	raw := patchBytes(nil, stringPtr(newUUID))
	patch, canonical, err := canonicalSemanticSidecarPatch(raw)
	if err != nil {
		t.Fatal(err)
	}
	if patch.SourceLineUUID != sourceUUID || string(canonical) != string(raw) {
		t.Fatalf("canonical patch mismatch: %s", canonical)
	}
	for _, invalid := range [][]byte{
		[]byte(`{"schema":"lattice.singbox-metadata.v2","source_line_uuid":"` + sourceUUID + `","source_inbound_tag":"source","desired_downstream_line_uuid":null}`),
		append(append([]byte(nil), raw...), '\n'),
		[]byte(strings.Replace(string(raw), sourceUUID, strings.ToUpper(sourceUUID), 1)),
	} {
		if _, _, err := canonicalSemanticSidecarPatch(invalid); err == nil {
			t.Fatalf("invalid patch accepted: %s", invalid)
		}
	}
}

func TestMergeManagedSidecarPreservesUnrelatedStateAndInboundFields(t *testing.T) {
	current := []byte(`{"schema":"lattice.singbox-metadata.v2","writer":"ordinary","unknown":{"keep":true},"inbounds":[{"tag":"other","line_uuid":"` + otherUUID + `","ordinary":"keep"},{"tag":"source","line_uuid":"` + sourceUUID + `","chain":{"downstream_line_uuid":"` + oldUUID + `","discard":"old"},"local":"preserve"}]}`)
	patch, _, _ := canonicalSemanticSidecarPatch(patchBytes(stringPtr(oldUUID), stringPtr(newUUID)))
	out, err := mergeManagedSidecar(current, patch)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got["writer"] != "ordinary" || got["unknown"].(map[string]any)["keep"] != true {
		t.Fatalf("top-level state lost: %s", out)
	}
	inbounds := got["inbounds"].([]any)
	if len(inbounds) != 2 || inbounds[0].(map[string]any)["ordinary"] != "keep" || inbounds[1].(map[string]any)["local"] != "preserve" {
		t.Fatalf("unrelated state changed: %s", out)
	}
	chain := inbounds[1].(map[string]any)["chain"].(map[string]any)
	if chain["downstream_line_uuid"] != newUUID || len(chain) != 1 {
		t.Fatalf("chain was not replaced exactly: %s", out)
	}
}

func TestMergeManagedSidecarRemoveDeletesOnlyChain(t *testing.T) {
	current := []byte(`{"schema":"lattice.singbox-metadata.v2","inbounds":[{"tag":"source","line_uuid":"` + sourceUUID + `","chain":{"downstream_line_uuid":"` + oldUUID + `"},"keep":true}]}`)
	patch, _, _ := canonicalSemanticSidecarPatch(patchBytes(stringPtr(oldUUID), nil))
	out, err := mergeManagedSidecar(current, patch)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "chain") || !strings.Contains(string(out), `"keep":true`) {
		t.Fatalf("remove changed more than chain: %s", out)
	}
}

func TestMergeManagedSidecarRejectsIdentityAndBaseDrift(t *testing.T) {
	patch, _, _ := canonicalSemanticSidecarPatch(patchBytes(stringPtr(oldUUID), stringPtr(newUUID)))
	cases := []string{
		`{"schema":"lattice.singbox-metadata.v2","inbounds":[{"tag":"source","line_uuid":"` + otherUUID + `"}]}`,
		`{"schema":"lattice.singbox-metadata.v2","inbounds":[{"tag":"one","line_uuid":"` + sourceUUID + `"},{"tag":"two","line_uuid":"` + sourceUUID + `"}]}`,
		`{"schema":"lattice.singbox-metadata.v2","inbounds":[{"tag":"source","line_uuid":"` + sourceUUID + `","chain":{"downstream_line_uuid":null}}]}`,
		`{"schema":"lattice.singbox-metadata.v2","inbounds":[{"tag":"other","line_uuid":"` + otherUUID + `"}]}`,
	}
	for _, current := range cases {
		if _, err := mergeManagedSidecar([]byte(current), patch); err == nil {
			t.Fatalf("invalid identity/base accepted: %s", current)
		}
	}
}

func TestSemanticBindingNeverRewritesIssuedDigests(t *testing.T) {
	fragment := `{"outbounds":[]}`
	patch := patchBytes(nil, stringPtr(newUUID))
	issued := semanticSidecarBinding{PatchSHA256: digest(patch), ArtifactSHA256: semanticArtifactDigest(&fragment, patch)}
	if err := verifySemanticSidecarBinding(&fragment, patch, issued); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*semanticSidecarBinding){
		"patch":    func(v *semanticSidecarBinding) { v.PatchSHA256 = digest([]byte("other")) },
		"artifact": func(v *semanticSidecarBinding) { v.ArtifactSHA256 = digest([]byte("other")) },
	} {
		t.Run(name, func(t *testing.T) {
			mismatch := issued
			mutate(&mismatch)
			before := mismatch
			if err := verifySemanticSidecarBinding(&fragment, patch, mismatch); err == nil {
				t.Fatal("mismatch accepted")
			}
			if mismatch != before {
				t.Fatalf("issued digest rewritten: %+v -> %+v", before, mismatch)
			}
		})
	}
}
