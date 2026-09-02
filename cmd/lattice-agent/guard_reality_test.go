package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"regexp"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/guardreality"
	"github.com/LatticeNet/lattice-sdk/model"
)

func TestWriteGuardManagedSHAOnlyOutputsCanonicalHashOnSuccess(t *testing.T) {
	valid := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tests := []struct {
		name    string
		collect func(context.Context, guardreality.Source) (string, error)
		want    string
		wantErr bool
	}{
		{
			name: "success",
			collect: func(context.Context, guardreality.Source) (string, error) {
				return valid, nil
			},
			want: valid + "\n",
		},
		{
			name: "collection failure",
			collect: func(context.Context, guardreality.Source) (string, error) {
				return "", errors.New("nft unavailable")
			},
			wantErr: true,
		},
		{
			name: "invalid collector value",
			collect: func(context.Context, guardreality.Source) (string, error) {
				return "NOT-A-SHA", nil
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := writeGuardManagedSHA(context.Background(), &out, tc.collect)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr=%v", err, tc.wantErr)
			}
			if out.String() != tc.want {
				t.Fatalf("stdout = %q, want %q", out.String(), tc.want)
			}
			if out.Len() > 0 && !regexp.MustCompile(`^[0-9a-f]{64}\n$`).Match(out.Bytes()) {
				t.Fatalf("successful stdout is not one lowercase SHA-256: %q", out.String())
			}
		})
	}
}

func TestReportedCapabilitiesAdvertiseGuardManagedSHA(t *testing.T) {
	got := reportedCapabilities()
	if !reflect.DeepEqual(got, []string{durableTaskResultCapability, guardManagedSHACapability}) {
		t.Fatalf("reported capabilities = %#v", got)
	}
}

func TestReportGuardReality(t *testing.T) {
	originalClient := httpClient
	t.Cleanup(func() { httpClient = originalClient })

	t.Run("disabled", func(t *testing.T) {
		collectorCalls := 0
		requestCalls := 0
		httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			requestCalls++
			return testResponse(http.StatusOK, `{"ok":true}`), nil
		})}

		err := reportGuardReality(context.Background(), agentConfig{}, func(context.Context, guardreality.Source, string) (model.GuardNodeReality, error) {
			collectorCalls++
			return model.GuardNodeReality{}, errors.New("collector must not run")
		})
		if err != nil {
			t.Fatalf("disabled report error = %v", err)
		}
		if collectorCalls != 0 || requestCalls != 0 {
			t.Fatalf("disabled report calls = collector %d, requests %d; want zero", collectorCalls, requestCalls)
		}
	})

	t.Run("success", func(t *testing.T) {
		collectedAt := time.Date(2026, time.August, 4, 6, 15, 0, 0, time.UTC)
		wantReality := model.GuardNodeReality{
			NodeID: "node-a",
			Listeners: []model.GuardListener{{
				Protocol: "tcp",
				Port:     22,
				Address:  "::",
				Process:  "sshd",
			}},
			Interfaces:    []model.GuardInterface{{Name: "wg0", Addresses: []string{"2001:db8::2/128"}, Up: true}},
			ManagedSHA:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			ForeignTables: []string{"inet foreign"},
			NFTVersion:    "1.1.0",
			CollectedAt:   collectedAt,
		}
		var body struct {
			NodeID  string                 `json:"node_id"`
			Reality model.GuardNodeReality `json:"reality"`
		}
		requestCalls := 0
		httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			requestCalls++
			if r.Method != http.MethodPost || r.URL.Path != "/api/agent/guard-reality" {
				return testResponse(http.StatusBadRequest, "bad request target"), nil
			}
			if r.Header.Get("Authorization") != "Bearer node-secret" {
				return testResponse(http.StatusBadRequest, "missing bearer"), nil
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			return testResponse(http.StatusOK, `{"ok":true}`), nil
		})}

		collectorCalls := 0
		err := reportGuardReality(context.Background(), agentConfig{
			Server:             "http://lattice.test",
			NodeID:             "node-a",
			Token:              "node-secret",
			ReportGuardReality: true,
		}, func(_ context.Context, source guardreality.Source, nodeID string) (model.GuardNodeReality, error) {
			collectorCalls++
			if nodeID != "node-a" {
				t.Fatalf("collector node id = %q, want node-a", nodeID)
			}
			if source.SSHD == nil {
				t.Fatal("report must hand the collector the sshd facts step")
			}
			return wantReality, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if collectorCalls != 1 || requestCalls != 1 {
			t.Fatalf("success calls = collector %d, requests %d; want one each", collectorCalls, requestCalls)
		}
		if body.NodeID != "node-a" || !reflect.DeepEqual(body.Reality, wantReality) {
			t.Fatalf("unexpected report body: %+v", body)
		}
	})

	t.Run("collect_failure", func(t *testing.T) {
		requestCalls := 0
		httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			requestCalls++
			return testResponse(http.StatusOK, `{"ok":true}`), nil
		})}

		err := reportGuardReality(context.Background(), agentConfig{ReportGuardReality: true}, func(context.Context, guardreality.Source, string) (model.GuardNodeReality, error) {
			return model.GuardNodeReality{}, errors.New("nft unavailable")
		})
		requireErrorContains(t, err, "collect guard reality")
		requireErrorContains(t, err, "nft unavailable")
		if requestCalls != 0 {
			t.Fatalf("collection failure sent %d requests, want zero", requestCalls)
		}
	})

	t.Run("server_failure", func(t *testing.T) {
		requestCalls := 0
		httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			requestCalls++
			return testResponse(http.StatusServiceUnavailable, `{"error":{"code":"temporarily_unavailable","message":"retry later"}}`), nil
		})}

		err := reportGuardReality(context.Background(), agentConfig{
			Server:             "http://lattice.test",
			NodeID:             "node-a",
			Token:              "node-secret",
			ReportGuardReality: true,
		}, func(context.Context, guardreality.Source, string) (model.GuardNodeReality, error) {
			return model.GuardNodeReality{NodeID: "node-a", CollectedAt: time.Now().UTC()}, nil
		})
		requireErrorContains(t, err, "report guard reality")
		requireErrorContains(t, err, "503 Service Unavailable")
		if requestCalls != 1 {
			t.Fatalf("server failure requests = %d, want one", requestCalls)
		}
	})

	t.Run("next_cycle_after_failure", func(t *testing.T) {
		requestCalls := 0
		httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			requestCalls++
			return testResponse(http.StatusOK, `{"ok":true}`), nil
		})}
		collectorCalls := 0
		collect := func(context.Context, guardreality.Source, string) (model.GuardNodeReality, error) {
			collectorCalls++
			if collectorCalls == 1 {
				return model.GuardNodeReality{}, errors.New("temporary collection failure")
			}
			return model.GuardNodeReality{NodeID: "node-a", CollectedAt: time.Now().UTC()}, nil
		}
		cfg := agentConfig{
			Server:             "http://lattice.test",
			NodeID:             "node-a",
			Token:              "node-secret",
			ReportGuardReality: true,
		}

		firstErr := reportGuardReality(context.Background(), cfg, collect)
		requireErrorContains(t, firstErr, "temporary collection failure")
		if err := reportGuardReality(context.Background(), cfg, collect); err != nil {
			t.Fatalf("next cycle did not recover: %v", err)
		}
		if collectorCalls != 2 || requestCalls != 1 {
			t.Fatalf("two cycles made collector %d, requests %d calls; want 2 and 1", collectorCalls, requestCalls)
		}
	})

	t.Run("deadline_bounds_post", func(t *testing.T) {
		httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			return nil, r.Context().Err()
		})}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		started := time.Now()
		err := reportGuardReality(ctx, agentConfig{
			Server:             "http://lattice.test",
			NodeID:             "node-a",
			Token:              "node-secret",
			ReportGuardReality: true,
		}, func(context.Context, guardreality.Source, string) (model.GuardNodeReality, error) {
			return model.GuardNodeReality{NodeID: "node-a", CollectedAt: time.Now().UTC()}, nil
		})
		requireErrorContains(t, err, "report guard reality")
		requireErrorContains(t, err, "context deadline exceeded")
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("deadline took %s, want under one second", elapsed)
		}
	})
}
