package linechain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const semanticSidecarSchema = "lattice.singbox-metadata.v2"

var lowercaseUUIDv4RE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type semanticSidecarPatchV2 struct {
	Schema                     string  `json:"schema"`
	SourceLineUUID             string  `json:"source_line_uuid"`
	SourceInboundTag           string  `json:"source_inbound_tag"`
	ExpectedDownstreamLineUUID *string `json:"expected_downstream_line_uuid"`
	DesiredDownstreamLineUUID  *string `json:"desired_downstream_line_uuid"`
}

type semanticSidecarBinding struct {
	PatchSHA256    string
	ArtifactSHA256 string
}

func canonicalSemanticSidecarPatch(raw []byte) (semanticSidecarPatchV2, []byte, error) {
	var fields map[string]json.RawMessage
	if err := decodeJSONObject(raw, &fields); err != nil {
		return semanticSidecarPatchV2{}, nil, fmt.Errorf("decode semantic sidecar patch: %w", err)
	}
	for _, name := range []string{"schema", "source_line_uuid", "source_inbound_tag", "expected_downstream_line_uuid", "desired_downstream_line_uuid"} {
		if _, ok := fields[name]; !ok {
			return semanticSidecarPatchV2{}, nil, fmt.Errorf("semantic sidecar patch field %s must be present", name)
		}
	}
	if len(fields) != 5 {
		return semanticSidecarPatchV2{}, nil, fmt.Errorf("semantic sidecar patch has unknown fields")
	}
	var patch semanticSidecarPatchV2
	if err := json.Unmarshal(raw, &patch); err != nil {
		return semanticSidecarPatchV2{}, nil, fmt.Errorf("decode semantic sidecar patch: %w", err)
	}
	if patch.Schema != semanticSidecarSchema || !lowercaseUUIDv4RE.MatchString(patch.SourceLineUUID) || strings.TrimSpace(patch.SourceInboundTag) == "" || patch.SourceInboundTag != strings.TrimSpace(patch.SourceInboundTag) {
		return semanticSidecarPatchV2{}, nil, fmt.Errorf("semantic sidecar patch identity is invalid")
	}
	for _, value := range []*string{patch.ExpectedDownstreamLineUUID, patch.DesiredDownstreamLineUUID} {
		if value != nil && !lowercaseUUIDv4RE.MatchString(*value) {
			return semanticSidecarPatchV2{}, nil, fmt.Errorf("semantic sidecar downstream identity is invalid")
		}
	}
	canonical, err := json.Marshal(patch)
	if err != nil {
		return semanticSidecarPatchV2{}, nil, fmt.Errorf("encode semantic sidecar patch: %w", err)
	}
	if !bytes.Equal(raw, canonical) {
		return semanticSidecarPatchV2{}, nil, fmt.Errorf("semantic sidecar patch is not canonical")
	}
	return patch, canonical, nil
}

func semanticArtifactDigest(fragment *string, patch []byte) string {
	var raw []byte
	if fragment != nil {
		raw = append(raw, []byte(*fragment)...)
	}
	raw = append(raw, 0)
	raw = append(raw, patch...)
	return digest(raw)
}

func verifySemanticSidecarBinding(fragment *string, patch []byte, issued semanticSidecarBinding) error {
	checks := []struct{ label, want, got string }{
		{label: "patch", want: issued.PatchSHA256, got: digest(patch)},
		{label: "artifact", want: issued.ArtifactSHA256, got: semanticArtifactDigest(fragment, patch)},
	}
	for _, check := range checks {
		if !validSHA(check.want) || check.want != check.got {
			return fmt.Errorf("semantic sidecar %s digest binding mismatch", check.label)
		}
	}
	return nil
}

// mergeManagedSidecar applies one authenticated source patch to an existing
// metadata v2 sidecar. It changes only the matched inbound's chain object.
func mergeManagedSidecar(current []byte, patch semanticSidecarPatchV2) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := decodeJSONObject(current, &top); err != nil {
		return nil, fmt.Errorf("decode current semantic sidecar: %w", err)
	}
	if err := validateSemanticSidecarTop(top); err != nil {
		return nil, fmt.Errorf("current semantic sidecar: %w", err)
	}
	var inbounds []json.RawMessage
	if err := json.Unmarshal(top["inbounds"], &inbounds); err != nil {
		return nil, fmt.Errorf("decode current semantic sidecar inbounds: %w", err)
	}
	match := -1
	seenUUID := make(map[string]struct{}, len(inbounds))
	seenTag := make(map[string]struct{}, len(inbounds))
	for i, raw := range inbounds {
		uuid, tag, err := semanticInboundIdentity(raw)
		if err != nil {
			return nil, fmt.Errorf("current semantic sidecar inbound %d: %w", i, err)
		}
		if _, ok := seenUUID[uuid]; ok {
			return nil, fmt.Errorf("current semantic sidecar has duplicate line_uuid %q", uuid)
		}
		if _, ok := seenTag[tag]; ok {
			return nil, fmt.Errorf("current semantic sidecar has duplicate tag %q", tag)
		}
		seenUUID[uuid], seenTag[tag] = struct{}{}, struct{}{}
		if uuid == patch.SourceLineUUID || tag == patch.SourceInboundTag {
			if uuid != patch.SourceLineUUID || tag != patch.SourceInboundTag || match >= 0 {
				return nil, fmt.Errorf("current semantic sidecar source identity is ambiguous")
			}
			match = i
		}
	}
	if match < 0 {
		return nil, fmt.Errorf("current semantic sidecar source identity is missing")
	}
	var inbound map[string]json.RawMessage
	if err := decodeJSONObject(inbounds[match], &inbound); err != nil {
		return nil, err
	}
	currentDownstream, err := currentDownstreamIdentity(inbound)
	if err != nil {
		return nil, err
	}
	if !nullableStringEqual(currentDownstream, patch.ExpectedDownstreamLineUUID) {
		return nil, fmt.Errorf("current semantic sidecar downstream identity changed")
	}
	if patch.DesiredDownstreamLineUUID == nil {
		delete(inbound, "chain")
	} else {
		chain := struct {
			DownstreamLineUUID string `json:"downstream_line_uuid"`
		}{DownstreamLineUUID: *patch.DesiredDownstreamLineUUID}
		encoded, err := json.Marshal(chain)
		if err != nil {
			return nil, err
		}
		inbound["chain"] = encoded
	}
	encodedInbound, err := json.Marshal(inbound)
	if err != nil {
		return nil, err
	}
	inbounds[match] = encodedInbound
	encodedInbounds, err := json.Marshal(inbounds)
	if err != nil {
		return nil, err
	}
	top["inbounds"] = encodedInbounds
	out, err := json.Marshal(top)
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func currentDownstreamIdentity(inbound map[string]json.RawMessage) (*string, error) {
	raw, ok := inbound["chain"]
	if !ok {
		return nil, nil
	}
	var chain map[string]json.RawMessage
	if err := decodeJSONObject(raw, &chain); err != nil {
		return nil, fmt.Errorf("current semantic sidecar chain: %w", err)
	}
	rawDownstream, ok := chain["downstream_line_uuid"]
	if !ok {
		return nil, fmt.Errorf("current semantic sidecar chain downstream_line_uuid must be present")
	}
	if bytes.Equal(bytes.TrimSpace(rawDownstream), []byte("null")) {
		return nil, nil
	}
	var value string
	if err := json.Unmarshal(rawDownstream, &value); err != nil || !lowercaseUUIDv4RE.MatchString(value) {
		return nil, fmt.Errorf("current semantic sidecar downstream_line_uuid is invalid")
	}
	return &value, nil
}

func nullableStringEqual(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func validateSemanticSidecarTop(top map[string]json.RawMessage) error {
	var schema string
	if err := json.Unmarshal(top["schema"], &schema); err != nil || schema != semanticSidecarSchema {
		return fmt.Errorf("unsupported schema")
	}
	var inbounds []json.RawMessage
	if err := json.Unmarshal(top["inbounds"], &inbounds); err != nil || inbounds == nil {
		return fmt.Errorf("inbounds must be an array")
	}
	return nil
}

func semanticInboundIdentity(raw json.RawMessage) (string, string, error) {
	var value map[string]json.RawMessage
	if err := decodeJSONObject(raw, &value); err != nil {
		return "", "", err
	}
	var uuid, tag string
	if err := json.Unmarshal(value["line_uuid"], &uuid); err != nil || !lowercaseUUIDv4RE.MatchString(uuid) {
		return "", "", fmt.Errorf("line_uuid must be a lowercase UUIDv4 string")
	}
	if err := json.Unmarshal(value["tag"], &tag); err != nil || strings.TrimSpace(tag) == "" || tag != strings.TrimSpace(tag) {
		return "", "", fmt.Errorf("tag must be a non-empty canonical string")
	}
	return uuid, tag, nil
}

func decodeJSONObject(raw []byte, dst *map[string]json.RawMessage) error {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("must be a non-null object")
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return err
	}
	if *dst == nil {
		return fmt.Errorf("must be a non-null object")
	}
	return nil
}
