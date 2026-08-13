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
	b, err := json.Marshal(SidecarPatchV2{Schema: semanticSidecarPatchSchema, SourceLineUUID: sourceUUID, SourceInboundTag: "source", ExpectedDownstreamLineUUID: expected, DesiredDownstreamLineUUID: desired})
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

func TestSemanticArtifactBindingNeverRewritesIssuedDigests(t *testing.T) {
	fragment := `{"outbounds":[]}`
	patch := patchBytes(nil, stringPtr(newUUID))
	fragmentSHA := digest([]byte(fragment))
	binding := semanticArtifactBindingV2{
		Schema: semanticArtifactSchema, Operation: "create", FragmentBasename: "lattice-linechain-0123456789abcdef0123.json",
		PreviousFragmentSHA256: nil, FragmentSHA256: &fragmentSHA, SidecarPatchSHA256: digest(patch),
	}
	canonical, err := canonicalSemanticArtifactBinding(binding)
	if err != nil {
		t.Fatal(err)
	}
	issuedArtifactSHA := digest(canonical)
	if err := verifySemanticArtifactBinding(&fragment, patch, binding, issuedArtifactSHA); err != nil {
		t.Fatal(err)
	}
	t.Run("patch", func(t *testing.T) {
		mismatch := binding
		mismatch.SidecarPatchSHA256 = digest([]byte("other"))
		before := mismatch
		if err := verifySemanticArtifactBinding(&fragment, patch, mismatch, issuedArtifactSHA); err == nil {
			t.Fatal("patch mismatch accepted")
		}
		if mismatch != before {
			t.Fatalf("issued binding rewritten: %+v -> %+v", before, mismatch)
		}
	})
	for name, value := range map[string]string{
		"fragment": digest([]byte("other")),
		"artifact": digest([]byte("other artifact")),
	} {
		t.Run(name, func(t *testing.T) {
			mismatch := binding
			artifactSHA := issuedArtifactSHA
			if name == "fragment" {
				mismatch.FragmentSHA256 = &value
			} else {
				artifactSHA = value
			}
			before := mismatch
			if err := verifySemanticArtifactBinding(&fragment, patch, mismatch, artifactSHA); err == nil {
				t.Fatal("mismatch accepted")
			}
			if mismatch != before {
				t.Fatalf("issued binding rewritten: %+v -> %+v", before, mismatch)
			}
		})
	}
}

func TestCanonicalSemanticBindingMatchesServerVector(t *testing.T) {
	const (
		patchJSON    = `{"schema":"lattice.singbox-linechain-sidecar-patch.v1","source_line_uuid":"22222222-2222-4222-8222-222222222222","source_inbound_tag":"source-b","expected_downstream_line_uuid":null,"desired_downstream_line_uuid":"11111111-1111-4111-8111-111111111111"}`
		patchSHA     = "7394c9367aa36d0e37e1e6bb70d3de70afc1d6792f56754741ba118ca2137188"
		artifactJSON = `{"schema":"lattice.singbox-linechain-artifact.v2","operation":"create","fragment_basename":"lattice-linechain-0123456789abcdef0123.json","previous_fragment_sha256":null,"fragment_sha256":"0000000000000000000000000000000000000000000000000000000000000000","sidecar_patch_sha256":"7394c9367aa36d0e37e1e6bb70d3de70afc1d6792f56754741ba118ca2137188"}`
		artifactSHA  = "bb59094488756276a385921951eaac3e36dc604eb4a03c4cb2e1a52797aee261"
	)
	patch, canonicalPatch, err := canonicalSemanticSidecarPatch([]byte(patchJSON))
	if err != nil {
		t.Fatal(err)
	}
	if string(canonicalPatch) != patchJSON || digest(canonicalPatch) != patchSHA {
		t.Fatalf("server patch vector drift: bytes=%s sha=%s", canonicalPatch, digest(canonicalPatch))
	}
	zeroSHA := strings.Repeat("0", 64)
	canonicalArtifact, err := canonicalSemanticArtifactBinding(semanticArtifactBindingV2{
		Schema: semanticArtifactSchema, Operation: "create", FragmentBasename: "lattice-linechain-0123456789abcdef0123.json",
		FragmentSHA256: &zeroSHA, SidecarPatchSHA256: digest(canonicalPatch),
	})
	if err != nil {
		t.Fatal(err)
	}
	if patch.SourceLineUUID != "22222222-2222-4222-8222-222222222222" || string(canonicalArtifact) != artifactJSON || digest(canonicalArtifact) != artifactSHA {
		t.Fatalf("server artifact vector drift: bytes=%s sha=%s", canonicalArtifact, digest(canonicalArtifact))
	}
}
