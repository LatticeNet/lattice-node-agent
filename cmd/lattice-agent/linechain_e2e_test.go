//go:build linechain_e2e && (darwin || linux || freebsd || openbsd || netbsd)

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/linechain"
	"github.com/LatticeNet/lattice-node-agent/internal/singboxdiscover"
	"github.com/LatticeNet/lattice-sdk/model"
)

const (
	linechainE2EBinEnv          = "LATTICE_SINGBOX_E2E_BIN"
	linechainE2ERootEnv         = "LATTICE_LINECHAIN_E2E_ROOT"
	linechainE2EConfigEnv       = "LATTICE_LINECHAIN_E2E_CONFIG_DIR"
	linechainE2ESidecarEnv      = "LATTICE_LINECHAIN_E2E_SIDECAR"
	linechainE2EBPortEnv        = "LATTICE_LINECHAIN_E2E_B_PORT"
	linechainE2ETaskEnv         = "LATTICE_LINECHAIN_E2E_TASK"
	linechainE2ELeaseEnv        = "LATTICE_LINECHAIN_E2E_LEASE"
	linechainE2ECrashMarkerEnv  = "LATTICE_LINECHAIN_E2E_CRASH_MARKER"
	linechainE2ERecoveryResult  = "LATTICE_LINECHAIN_E2E_RECOVERY_RESULT"
	linechainE2EResolveResult   = "LATTICE_LINECHAIN_E2E_RESOLVE_RESULT"
	linechainE2EInventoryResult = "LATTICE_LINECHAIN_E2E_INVENTORY_RESULT"
)

var managedE2EProcesses = struct {
	sync.Mutex
	done map[int]<-chan error
}{done: make(map[int]<-chan error)}

// TestLinechainRealSingBoxE2E is invoked by scripts/test-linechain-e2e.sh. The
// script makes the real 1.13.x binary mandatory, so this test never skips.
func TestLinechainRealSingBoxE2E(t *testing.T) {
	bin := requireSingBoxE2EBinary(t)
	root := os.Getenv(linechainE2ERootEnv)
	if !filepath.IsAbs(root) {
		t.Fatalf("%s must be an absolute test root", linechainE2ERootEnv)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	origin := startEchoOrigin(t)
	aPort, bPort, clientPort := freePort(t), freePort(t), freePort(t)
	observer := startTCPObserver(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(aPort)))
	decoy := httptest.NewTLSServer(nil)
	t.Cleanup(decoy.Close)
	decoyAddress := strings.TrimPrefix(decoy.URL, "https://")
	decoyHost, decoyPortText, err := net.SplitHostPort(decoyAddress)
	if err != nil {
		t.Fatal(err)
	}
	decoyPort, err := strconv.Atoi(decoyPortText)
	if err != nil {
		t.Fatal(err)
	}
	realityPrivate, realityPublic := generateRealityKeypair(t, bin)
	const (
		uuidA     = "11111111-1111-4111-8111-111111111111"
		uuidB     = "22222222-2222-4222-8222-222222222222"
		lineUUIDA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		lineUUIDB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
		basename  = "lattice-linechain-0123456789abcdef0123.json"
	)

	aDir := filepath.Join(root, "a")
	bDir := filepath.Join(root, "b")
	clientDir := filepath.Join(root, "client")
	mustMkdir(t, aDir)
	mustMkdir(t, bDir)
	mustMkdir(t, clientDir)
	writeFile(t, filepath.Join(aDir, "config.json"), fmt.Sprintf(`{
  "log":{"level":"error"},
  "inbounds":[{"type":"vless","tag":"target-a","listen":"127.0.0.1","listen_port":%d,"users":[{"uuid":%q,"flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":"e2e.lattice.invalid","reality":{"enabled":true,"handshake":{"server":%q,"server_port":%d},"private_key":%q,"short_id":["0123456789abcdef"]}}}],
  "outbounds":[{"type":"direct","tag":"direct"}],
  "route":{"rules":[{"inbound":["target-a"],"outbound":"direct"}]}
}
`, aPort, uuidA, decoyHost, decoyPort, realityPrivate))
	writeFile(t, filepath.Join(bDir, "config.json"), fmt.Sprintf(`{
  "log":{"level":"error"},
  "inbounds":[{"type":"vless","tag":"source-b","listen":"127.0.0.1","listen_port":%d,"users":[{"uuid":%q}]}],
  "outbounds":[{"type":"direct","tag":"direct"}],
  "route":{"final":"direct"}
}
`, bPort, uuidB))
	writeFile(t, filepath.Join(clientDir, "config.json"), fmt.Sprintf(`{
  "log":{"level":"error"},
  "inbounds":[{"type":"socks","tag":"client","listen":"127.0.0.1","listen_port":%d}],
  "outbounds":[{"type":"vless","tag":"to-b","server":"127.0.0.1","server_port":%d,"uuid":%q}],
  "route":{"rules":[{"inbound":["client"],"outbound":"to-b"}]}
}
`, clientPort, bPort, uuidB))

	startManagedSingBox(t, bin, root, "a", aDir, aPort)
	if err := verifyManagedSingBox(root, "a", aPort); err != nil {
		t.Fatalf("managed target A is inactive: %v", err)
	}
	startManagedSingBox(t, bin, root, "b", bDir, bPort)
	startManagedSingBox(t, bin, root, "client", clientDir, clientPort)

	assertSOCKSEcho(t, clientPort, origin)
	if got := observer.Count(); got != 0 {
		t.Fatalf("B began chained: observer accepted %d connections before apply", got)
	}

	sidecarPath := filepath.Join(root, "lattice-metadata.json")
	fragmentPath := filepath.Join(bDir, basename)
	txnDir := filepath.Join(root, "txn")
	fragment := fmt.Sprintf(`{
  "outbounds":[{"type":"vless","tag":"chain-to-a","server":"127.0.0.1","server_port":%d,"uuid":%q,"flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"e2e.lattice.invalid","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":%q,"short_id":"0123456789abcdef"}}}],
  "route":{"rules":[{"inbound":["source-b"],"outbound":"chain-to-a"}]}
}
`, observer.Port(), uuidA, realityPublic)
	initialSidecar := canonicalJSONString(t, fmt.Sprintf(`{"schema":"lattice.singbox-metadata.v2","unknown_root":{"keep":true},"inbounds":[{"tag":"unrelated-before","line_uuid":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","keep":1},{"tag":"source-b","line_uuid":%q,"ordinary":"keep"},{"tag":"unrelated-after","line_uuid":"dddddddd-dddd-4ddd-8ddd-dddddddddddd","keep":2}]}`, lineUUIDB))
	desiredSidecar := canonicalJSONString(t, fmt.Sprintf(`{"schema":"lattice.singbox-metadata.v2","unknown_root":{"keep":true},"inbounds":[{"tag":"unrelated-before","line_uuid":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","keep":1},{"tag":"source-b","line_uuid":%q,"ordinary":"keep","chain":{"downstream_line_uuid":%q}},{"tag":"unrelated-after","line_uuid":"dddddddd-dddd-4ddd-8ddd-dddddddddddd","keep":2}]}`, lineUUIDB, lineUUIDA))
	writeFile(t, sidecarPath, initialSidecar)
	targetLineUUID := lineUUIDA

	m := openE2EManager(t, bin, root, bDir, sidecarPath, txnDir, bPort)
	defer m.Close()

	// Crash a real apply helper process group after it publishes both artifacts,
	// while this test (the agent/supervisor analogue) remains alive. Recovery
	// must restore and restart B before any inventory, traffic, or result callback.
	crashDoc := bindE2EDocument("create", basename, "", &fragment, lineUUIDB, "source-b", nil, &targetLineUUID)
	crashBytes := marshalE2EDocument(t, crashDoc)
	apply := exec.Command(os.Args[0], "-test.run=^TestLinechainE2EApplyHelper$", "--", root)
	crashMarker := filepath.Join(root, "restart-blocked")
	apply.Env = append(os.Environ(),
		linechainE2EBinEnv+"="+bin,
		linechainE2ERootEnv+"="+root,
		linechainE2EConfigEnv+"="+bDir,
		linechainE2ESidecarEnv+"="+sidecarPath,
		linechainE2EBPortEnv+"="+strconv.Itoa(bPort),
		linechainE2ETaskEnv+"=crash-task",
		linechainE2ELeaseEnv+"=crash-lease",
		"LATTICE_LINECHAIN_TASK_SCRIPT_SHA256="+digestText("e2e-helper-script"),
		linechainE2ECrashMarkerEnv+"="+crashMarker,
	)
	apply.Stdin = bytes.NewReader(crashBytes)
	apply.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var applyLog bytes.Buffer
	apply.Stdout, apply.Stderr = &applyLog, &applyLog
	if err := apply.Start(); err != nil {
		t.Fatal(err)
	}
	applyDone := make(chan error, 1)
	go func() { applyDone <- apply.Wait() }()
	var cleanupApply sync.Once
	stopApply := func() {
		cleanupApply.Do(func() {
			_ = syscall.Kill(-apply.Process.Pid, syscall.SIGKILL)
			select {
			case <-applyDone:
			case <-time.After(5 * time.Second):
				t.Errorf("apply helper did not exit after process-group kill")
			}
			killMarkerProcess(t, crashMarker)
		})
	}
	t.Cleanup(stopApply)
	waitForFileOrProcess(t, crashMarker, applyDone, &applyLog)
	waitForExactPair(t, fragmentPath, fragment, sidecarPath, desiredSidecar)
	stopApply()

	order := []string{}
	if err := m.RequireRecovered(context.Background(), func(result model.TaskResult) error {
		order = append(order, "result")
		if result.ExitCode == 0 || !strings.Contains(result.Error, "interrupted") {
			return fmt.Errorf("unexpected recovered result: %+v", result)
		}
		return nil
	}, "node-b"); err != nil {
		t.Fatalf("recover killed helper: %v (helper output %s)", err, applyLog.String())
	}
	order = append(order, "inventory")
	assertUnchainedInventory(t, bDir, sidecarPath)
	order = append(order, "traffic")
	assertSOCKSEcho(t, clientPort, origin)
	if strings.Join(order, ",") != "result,inventory,traffic" {
		t.Fatalf("recovery ordering = %v", order)
	}
	if got := observer.Count(); got != 0 {
		t.Fatalf("recovery exposed chained traffic before successful apply: %d", got)
	}

	applyAndResolve(t, m, marshalE2EDocument(t, crashDoc), "create-task", "create-lease")
	if err := verifyManagedSingBox(root, "a", aPort); err != nil {
		t.Fatalf("managed target A became inactive after apply: %v", err)
	}
	assertSOCKSEcho(t, clientPort, origin)
	if got := observer.Count(); got == 0 {
		t.Fatal("traffic did not traverse the B-to-A observer after apply")
	}
	assertChainedInventory(t, bDir, fragmentPath, sidecarPath, lineUUIDB, lineUUIDA, observer.Port())

	// Simulate the ordinary independent metadata writer changing unrelated
	// sidecar bytes. The declared edge remains intact, and remove must tolerate
	// this non-E3 sidecar drift instead of applying a stale sidecar CAS.
	resyncedSidecar := fmt.Sprintf(`{"generated_by":"ordinary-resync","inbounds":[{"tag":"source-b","line_uuid":%q,"chain":{"downstream_line_uuid":%q}}],"schema":"lattice.singbox-metadata.v2"}
`, lineUUIDB, lineUUIDA)
	writeFile(t, sidecarPath, resyncedSidecar)
	assertChainedInventory(t, bDir, fragmentPath, sidecarPath, lineUUIDB, lineUUIDA, observer.Port())

	removeDoc := bindE2EDocument("remove", basename, digestText(fragment), nil, lineUUIDB, "source-b", &targetLineUUID, nil)
	applyAndResolve(t, m, marshalE2EDocument(t, removeDoc), "remove-task", "remove-lease")
	if _, err := os.Stat(fragmentPath); !os.IsNotExist(err) {
		t.Fatalf("removed fragment still exists: %v", err)
	}
	assertUnchainedInventory(t, bDir, sidecarPath)
	before := observer.Count()
	assertSOCKSEcho(t, clientPort, origin)
	if got := observer.Count(); got != before {
		t.Fatalf("traffic still used A after remove: observer %d -> %d", before, got)
	}
}

// TestLinechainE2EApplyHelper is a child-only entry point used to create a real
// crash boundary. The parent test kills this process group, not the supervisor.
func TestLinechainE2EApplyHelper(t *testing.T) {
	if os.Getenv(linechainE2ETaskEnv) == "" {
		return
	}
	m, err := linechain.OpenHelper(filepath.Join(os.Getenv(linechainE2ERootEnv), "txn"))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	configureE2EManager(t, m)
	if err := m.Apply(context.Background(), os.Stdin, os.Getenv(linechainE2ETaskEnv), os.Getenv(linechainE2ELeaseEnv), os.Getenv("LATTICE_LINECHAIN_TASK_SCRIPT_SHA256")); err != nil {
		t.Fatal(err)
	}
}

// TestLinechainE2ERecoverHelper is a child-only startup recovery entry point.
// It writes the recovered result only after RequireRecovered has restored the
// old artifacts and restarted the managed B process.
func TestLinechainE2ERecoverHelper(t *testing.T) {
	resultPath := os.Getenv(linechainE2ERecoveryResult)
	if resultPath == "" {
		return
	}
	root := mustAbsoluteEnv(t, linechainE2ERootEnv)
	consumeE2ECrashMarker(t, mustAbsoluteEnv(t, linechainE2ECrashMarkerEnv))
	m := openE2EManager(t, mustExecutableEnv(t, linechainE2EBinEnv), root, mustAbsoluteEnv(t, linechainE2EConfigEnv), mustAbsoluteEnv(t, linechainE2ESidecarEnv), filepath.Join(root, "txn"), mustEnvPort(linechainE2EBPortEnv))
	defer m.Close()
	var recovered model.TaskResult
	called := false
	if err := m.RequireRecovered(context.Background(), func(result model.TaskResult) error {
		called = true
		recovered = result
		return nil
	}, "node-b"); err != nil {
		t.Fatal(err)
	}
	if !called || recovered.TaskID == "" || recovered.LeaseID == "" {
		t.Fatalf("recovery emitted no exact task result: %+v", recovered)
	}
	writeE2EJSON(t, resultPath, recovered)
}

// TestLinechainE2EResolveHelper converts a successful helper run into the
// stable durable result, cleans its journal, and only then publishes JSON.
func TestLinechainE2EResolveHelper(t *testing.T) {
	resultPath := os.Getenv(linechainE2EResolveResult)
	if resultPath == "" {
		return
	}
	root := mustAbsoluteEnv(t, linechainE2ERootEnv)
	taskID := mustEnv(t, linechainE2ETaskEnv)
	leaseID := mustEnv(t, linechainE2ELeaseEnv)
	m := openE2EManager(t, mustExecutableEnv(t, linechainE2EBinEnv), root, mustAbsoluteEnv(t, linechainE2EConfigEnv), mustAbsoluteEnv(t, linechainE2ESidecarEnv), filepath.Join(root, "txn"), mustEnvPort(linechainE2EBPortEnv))
	defer m.Close()
	result, err := m.ResolveAfterRun(context.Background(), model.Task{ID: taskID, LeaseID: leaseID}, model.TaskResult{TaskID: taskID, LeaseID: leaseID, ExitCode: 0, FinishedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Cleanup(taskID, leaseID); err != nil {
		t.Fatal(err)
	}
	writeE2EJSON(t, resultPath, result)
}

// TestLinechainE2EInventoryHelper publishes the inventory discovered from the
// actual post-restart config directory and semantic sidecar.
func TestLinechainE2EInventoryHelper(t *testing.T) {
	resultPath := os.Getenv(linechainE2EInventoryResult)
	if resultPath == "" {
		return
	}
	configDir := mustAbsoluteEnv(t, linechainE2EConfigEnv)
	paths, err := filepath.Glob(filepath.Join(configDir, "*.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("discover config files: paths=%v err=%v", paths, err)
	}
	inv, err := singboxdiscover.DiscoverRuntimeFiles("node-b", paths, mustAbsoluteEnv(t, linechainE2ESidecarEnv))
	if err != nil {
		t.Fatal(err)
	}
	writeE2EJSON(t, resultPath, inv)
}

// TestLinechainE2ERestartHelper is the fixed restart/active command used by the
// Manager. It stops the prior B instance and starts a checked replacement.
func TestLinechainE2ERestartHelper(t *testing.T) {
	if os.Getenv(linechainE2ERootEnv) == "" {
		return
	}
	root := mustAbsoluteEnv(t, linechainE2ERootEnv)
	if marker := os.Getenv(linechainE2ECrashMarkerEnv); marker != "" {
		if !filepath.IsAbs(marker) {
			t.Fatalf("%s must be absolute", linechainE2ECrashMarkerEnv)
		}
		if err := os.WriteFile(marker, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		for {
			time.Sleep(time.Hour)
		}
	}
	if err := restartManagedSingBox(mustExecutableEnv(t, linechainE2EBinEnv), root, "b", mustAbsoluteEnv(t, linechainE2EConfigEnv), mustEnvPort(linechainE2EBPortEnv)); err != nil {
		t.Fatal(err)
	}
}

func mustEnv(t *testing.T, key string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		t.Fatalf("%s is required", key)
	}
	return value
}

func mustAbsoluteEnv(t *testing.T, key string) string {
	t.Helper()
	value := mustEnv(t, key)
	if !filepath.IsAbs(value) {
		t.Fatalf("%s must be absolute", key)
	}
	return value
}

func mustExecutableEnv(t *testing.T, key string) string {
	t.Helper()
	value := mustAbsoluteEnv(t, key)
	info, err := os.Stat(value)
	if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		t.Fatalf("%s must be executable: %v", key, err)
	}
	return value
}

func writeE2EJSON(t *testing.T, path string, value any) {
	t.Helper()
	if !filepath.IsAbs(path) {
		t.Fatalf("result path must be absolute: %s", path)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func consumeE2ECrashMarker(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read one-shot crash marker: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 1 {
		t.Fatalf("invalid one-shot crash marker %q", raw)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("consume one-shot crash marker: %v", err)
	}
	if err := os.Unsetenv(linechainE2ECrashMarkerEnv); err != nil {
		t.Fatalf("clear one-shot crash marker env: %v", err)
	}
}

func TestLinechainE2EActiveHelper(t *testing.T) {
	root := os.Getenv(linechainE2ERootEnv)
	if root == "" {
		return
	}
	if err := verifyManagedSingBox(root, "b", mustEnvPort(linechainE2EBPortEnv)); err != nil {
		t.Fatal(err)
	}
}

type e2eDocument map[string]any

type e2eSidecarPatch struct {
	Schema, SourceLineUUID, SourceInboundTag              string
	ExpectedDownstreamLineUUID, DesiredDownstreamLineUUID *string
}

func (p e2eSidecarPatch) MarshalJSON() ([]byte, error) {
	type wire struct {
		Schema           string  `json:"schema"`
		SourceLineUUID   string  `json:"source_line_uuid"`
		SourceInboundTag string  `json:"source_inbound_tag"`
		Expected         *string `json:"expected_downstream_line_uuid"`
		Desired          *string `json:"desired_downstream_line_uuid"`
	}
	return json.Marshal(wire{p.Schema, p.SourceLineUUID, p.SourceInboundTag, p.ExpectedDownstreamLineUUID, p.DesiredDownstreamLineUUID})
}

func bindE2EDocument(operation, basename, previousFragment string, fragment *string, sourceUUID, sourceTag string, expected, desired *string) e2eDocument {
	patch := e2eSidecarPatch{"lattice.singbox-linechain-sidecar-patch.v1", sourceUUID, sourceTag, expected, desired}
	patchBytes, _ := json.Marshal(patch)
	var previous *string
	if previousFragment != "" {
		previous = &previousFragment
	}
	var fragmentSHA *string
	if fragment != nil {
		value := digestText(*fragment)
		fragmentSHA = &value
	}
	patchSHA := digestBytes(patchBytes)
	type artifact struct {
		Schema    string  `json:"schema"`
		Operation string  `json:"operation"`
		Basename  string  `json:"fragment_basename"`
		Previous  *string `json:"previous_fragment_sha256"`
		Fragment  *string `json:"fragment_sha256"`
		Patch     string  `json:"sidecar_patch_sha256"`
	}
	artifactBytes, _ := json.Marshal(artifact{"lattice.singbox-linechain-artifact.v2", operation, basename, previous, fragmentSHA, patchSHA})
	d := e2eDocument{"version": 2, "durable_protocol": "linechain-e3-v2", "operation": operation, "fragment_basename": basename, "fragment": fragment, "sidecar_patch": patch, "previous_fragment_sha256": previous, "fragment_sha256": fragmentSHA, "sidecar_patch_sha256": patchSHA, "artifact_sha256": digestBytes(artifactBytes)}
	return d
}

func marshalE2EDocument(t *testing.T, d e2eDocument) []byte {
	t.Helper()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func canonicalJSONString(t *testing.T, raw string) string {
	t.Helper()
	var value any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(append(b, '\n'))
}

func openE2EManager(t *testing.T, bin, root, configDir, sidecarPath, txnDir string, bPort int) *linechain.Manager {
	t.Helper()
	for key, value := range map[string]string{
		linechainE2EBinEnv: bin, linechainE2ERootEnv: root, linechainE2EConfigEnv: configDir,
		linechainE2ESidecarEnv: sidecarPath, linechainE2EBPortEnv: strconv.Itoa(bPort),
	} {
		t.Setenv(key, value)
	}
	m, err := linechain.Open(txnDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ConfigureLayout(configDir, sidecarPath); err != nil {
		t.Fatal(err)
	}
	configureE2EManager(t, m)
	return m
}

func configureE2EManager(t *testing.T, m *linechain.Manager) {
	t.Helper()
	if err := m.ConfigureLayout(os.Getenv(linechainE2EConfigEnv), os.Getenv(linechainE2ESidecarEnv)); err != nil {
		t.Fatal(err)
	}
	root := os.Getenv(linechainE2ERootEnv)
	restart := []string{os.Args[0], "-test.run=^TestLinechainE2ERestartHelper$", "--", root}
	verify := []string{os.Args[0], "-test.run=^TestLinechainE2EActiveHelper$", "--", root}
	if err := m.ConfigureCommands(os.Getenv(linechainE2EBinEnv), restart, verify); err != nil {
		t.Fatal(err)
	}
}

func applyAndResolve(t *testing.T, m *linechain.Manager, document []byte, taskID, leaseID string) {
	t.Helper()
	if err := m.Apply(context.Background(), bytes.NewReader(document), taskID, leaseID, digestText("e2e-direct:"+taskID)); err != nil {
		t.Fatal(err)
	}
	result, err := m.ResolveAfterRun(context.Background(), model.Task{ID: taskID, LeaseID: leaseID}, model.TaskResult{TaskID: taskID, LeaseID: leaseID, ExitCode: 0})
	if err != nil || result.ExitCode != 0 || result.Error != "" {
		t.Fatalf("resolve %s: result=%+v err=%v", taskID, result, err)
	}
	if err := m.Cleanup(taskID, leaseID); err != nil {
		t.Fatalf("cleanup %s: %v", taskID, err)
	}
}

func assertChainedInventory(t *testing.T, configDir, fragmentPath, sidecarPath, lineUUIDB, lineUUIDA string, observerPort int) {
	t.Helper()
	inv, err := singboxdiscover.DiscoverRuntimeFiles("node-b", []string{filepath.Join(configDir, "config.json"), fragmentPath}, sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	n := findInventoryNode(t, inv, "source-b")
	if n.OutboundRef != "chain-to-a" || n.OutboundServer != "127.0.0.1" || n.OutboundPort != strconv.Itoa(observerPort) || n.OutboundType != "vless" {
		t.Fatalf("discovered outbound identity mismatch: %+v", n)
	}
	if n.LineUUID != lineUUIDB || n.DownstreamLineUUID != lineUUIDA {
		t.Fatalf("discovered sidecar identity mismatch: %+v", n)
	}
}

func assertUnchainedInventory(t *testing.T, configDir, sidecarPath string) {
	t.Helper()
	inv, err := singboxdiscover.DiscoverRuntimeFiles("node-b", []string{filepath.Join(configDir, "config.json")}, sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	n := findInventoryNode(t, inv, "source-b")
	if n.OutboundRef != "" || n.OutboundServer != "" || n.OutboundPort != "" || n.DownstreamLineUUID != "" {
		t.Fatalf("expected unchained inventory, got %+v", n)
	}
}

func findInventoryNode(t *testing.T, inv model.SingBoxInventory, name string) model.SingBoxNode {
	t.Helper()
	for _, n := range inv.Nodes {
		if n.Name == name {
			return n
		}
	}
	t.Fatalf("inventory lacks %q: %+v", name, inv.Nodes)
	return model.SingBoxNode{}
}

func generateRealityKeypair(t *testing.T, bin string) (string, string) {
	t.Helper()
	out, err := exec.Command(bin, "generate", "reality-keypair").CombinedOutput()
	if err != nil {
		t.Fatalf("generate reality keypair: %v: %s", err, out)
	}
	var privateKey, publicKey string
	for _, line := range strings.Split(string(out), "\n") {
		if value, ok := strings.CutPrefix(line, "PrivateKey: "); ok {
			privateKey = strings.TrimSpace(value)
		}
		if value, ok := strings.CutPrefix(line, "PublicKey: "); ok {
			publicKey = strings.TrimSpace(value)
		}
	}
	if privateKey == "" || publicKey == "" {
		t.Fatalf("unexpected reality keypair output: %s", out)
	}
	return privateKey, publicKey
}

func requireSingBoxE2EBinary(t *testing.T) string {
	t.Helper()
	bin := os.Getenv(linechainE2EBinEnv)
	if bin == "" || !filepath.IsAbs(bin) {
		t.Fatalf("%s must name an absolute official sing-box 1.13.x binary", linechainE2EBinEnv)
	}
	out, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "sing-box version 1.13.") {
		t.Fatalf("%s is not sing-box 1.13.x: %v\n%s", bin, err, out)
	}
	return bin
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startEchoOrigin(t *testing.T) *net.TCPAddr {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().(*net.TCPAddr)
}

type tcpObserver struct {
	listener net.Listener
	count    chan struct{}
}

func startTCPObserver(t *testing.T, target string) *tcpObserver {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	o := &tcpObserver{listener: l, count: make(chan struct{}, 128)}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			incoming, err := l.Accept()
			if err != nil {
				return
			}
			o.count <- struct{}{}
			go func() {
				defer incoming.Close()
				upstream, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer upstream.Close()
				go func() { _, _ = io.Copy(upstream, incoming); _ = upstream.(*net.TCPConn).CloseWrite() }()
				_, _ = io.Copy(incoming, upstream)
			}()
		}
	}()
	return o
}

func (o *tcpObserver) Port() int { return o.listener.Addr().(*net.TCPAddr).Port }
func (o *tcpObserver) Count() int {
	n := 0
	for {
		select {
		case <-o.count:
			n++
		default:
			return n
		}
	}
}

func startManagedSingBox(t *testing.T, bin, root, name, configDir string, port int) {
	t.Helper()
	if err := restartManagedSingBox(bin, root, name, configDir, port); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := killManagedSingBox(root, name); err != nil {
			t.Errorf("cleanup managed sing-box %s: %v", name, err)
		}
	})
}

func restartManagedSingBox(bin, root, name, configDir string, port int) error {
	if err := killManagedSingBox(root, name); err != nil {
		return err
	}
	logPath := filepath.Join(root, name+".log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, "run", "-C", configDir)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return err
	}
	done := make(chan error, 1)
	managedE2EProcesses.Lock()
	managedE2EProcesses.done[cmd.Process.Pid] = done
	managedE2EProcesses.Unlock()
	go func() { done <- cmd.Wait() }()
	_ = logFile.Close()
	if err := os.WriteFile(filepath.Join(root, name+".pid"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		exited := waitManagedProcess(cmd.Process.Pid, done, 2*time.Second)
		managedE2EProcesses.Lock()
		delete(managedE2EProcesses.done, cmd.Process.Pid)
		managedE2EProcesses.Unlock()
		if !exited {
			return fmt.Errorf("write %s pid file: %w; process group %d remained after SIGKILL", name, err, cmd.Process.Pid)
		}
		return err
	}
	if err := waitForPort(port, 8*time.Second); err != nil {
		cleanupErr := killManagedSingBox(root, name)
		logBytes, _ := os.ReadFile(logPath)
		if cleanupErr != nil {
			return fmt.Errorf("start %s: %w: %s; cleanup: %v", name, err, logBytes, cleanupErr)
		}
		return fmt.Errorf("start %s: %w: %s", name, err, logBytes)
	}
	return nil
}

func killManagedSingBox(root, name string) (retErr error) {
	pidPath := filepath.Join(root, name+".pid")
	raw, err := os.ReadFile(pidPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 1 {
		parseErr := fmt.Errorf("invalid %s pid %q", name, raw)
		if removeErr := os.Remove(pidPath); removeErr != nil && !os.IsNotExist(removeErr) {
			return fmt.Errorf("%v; remove invalid pid file: %w", parseErr, removeErr)
		}
		return parseErr
	}
	managedE2EProcesses.Lock()
	done := managedE2EProcesses.done[pid]
	managedE2EProcesses.Unlock()
	defer func() {
		managedE2EProcesses.Lock()
		delete(managedE2EProcesses.done, pid)
		managedE2EProcesses.Unlock()
		if err := os.Remove(pidPath); err != nil && !os.IsNotExist(err) {
			if retErr == nil {
				retErr = fmt.Errorf("remove %s pid file: %w", name, err)
			} else {
				retErr = fmt.Errorf("%v; remove %s pid file: %w", retErr, name, err)
			}
		}
	}()
	if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil && err != syscall.ESRCH {
		return err
	}
	if waitManagedProcess(pid, done, 2*time.Second) {
		return nil
	}
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
		return err
	}
	if waitManagedProcess(pid, done, 2*time.Second) {
		return nil
	}
	return fmt.Errorf("%s process %d remained after SIGKILL", name, pid)
}

func waitManagedProcess(pid int, done <-chan error, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if done != nil {
			select {
			case <-done:
				return true
			default:
			}
		} else if syscall.Kill(-pid, 0) == syscall.ESRCH {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func TestKillManagedSingBoxTerminatesProcessGroupAndClearsState(t *testing.T) {
	root := t.TempDir()
	cmd := exec.Command("sh", "-c", "trap 'exit 0' TERM; sleep 60 & wait")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	managedE2EProcesses.Lock()
	managedE2EProcesses.done[cmd.Process.Pid] = done
	managedE2EProcesses.Unlock()
	go func() { done <- cmd.Wait() }()
	pidPath := filepath.Join(root, "test.pid")
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := killManagedSingBox(root, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("pid file survived cleanup: %v", err)
	}
	managedE2EProcesses.Lock()
	_, tracked := managedE2EProcesses.done[cmd.Process.Pid]
	managedE2EProcesses.Unlock()
	if tracked {
		t.Fatal("managed process survived in reap map")
	}
	if err := syscall.Kill(-cmd.Process.Pid, 0); err != syscall.ESRCH {
		t.Fatalf("managed process group survived cleanup: %v", err)
	}
}

func TestKillManagedSingBoxRejectsAndRemovesInvalidPID(t *testing.T) {
	root := t.TempDir()
	pidPath := filepath.Join(root, "invalid.pid")
	if err := os.WriteFile(pidPath, []byte("not-a-pid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := killManagedSingBox(root, "invalid"); err == nil || !strings.Contains(err.Error(), "invalid invalid pid") {
		t.Fatalf("invalid pid error = %v", err)
	}
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("invalid pid file survived cleanup: %v", err)
	}
}

func killMarkerProcess(t *testing.T, marker string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(marker)
		if os.IsNotExist(err) {
			return
		}
		if err != nil {
			t.Errorf("read helper marker: %v", err)
			return
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
		if err != nil || pid <= 1 {
			t.Errorf("invalid helper marker %q", raw)
			return
		}
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		_ = syscall.Kill(pid, syscall.SIGKILL)
		if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
			_ = os.Remove(marker)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("restart helper from %s remained after cleanup", marker)
}

func verifyManagedSingBox(root, name string, port int) error {
	raw, err := os.ReadFile(filepath.Join(root, name+".pid"))
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 1 {
		return fmt.Errorf("invalid pid %q", raw)
	}
	if err := syscall.Kill(pid, 0); err != nil {
		return fmt.Errorf("sing-box process inactive: %w", err)
	}
	return waitForPort(port, time.Second)
}

func waitForPort(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("port %d did not become ready", port)
}

func waitForFileOrProcess(t *testing.T, path string, done <-chan error, output *bytes.Buffer) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("apply helper exited before crash marker: %v: %s", err, output.String())
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for helper signal %s: %s", path, output.String())
}

func waitForExactPair(t *testing.T, fragmentPath, fragment, sidecarPath, sidecar string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		f, ferr := os.ReadFile(fragmentPath)
		s, serr := os.ReadFile(sidecarPath)
		if ferr == nil && serr == nil && string(f) == fragment && string(s) == sidecar {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	f, ferr := os.ReadFile(fragmentPath)
	s, serr := os.ReadFile(sidecarPath)
	t.Fatalf("apply helper did not publish exact pair: fragment err=%v got=%q want=%q; sidecar err=%v got=%q want=%q", ferr, f, fragment, serr, s, sidecar)
}

func mustEnvPort(key string) int {
	port, err := strconv.Atoi(os.Getenv(key))
	if err != nil || port < 1 || port > 65535 {
		panic("invalid " + key)
	}
	return port
}

func digestText(s string) string { return digestBytes([]byte(s)) }
func digestPointer(s *string) string {
	if s == nil {
		return ""
	}
	return digestText(*s)
}
func digestBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func assertSOCKSEcho(t *testing.T, socksPort int, target *net.TCPAddr) {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err = io.ReadFull(c, reply); err != nil || !bytes.Equal(reply, []byte{5, 0}) {
		t.Fatalf("SOCKS greeting: %v %v", reply, err)
	}
	req := []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(req[8:], uint16(target.Port))
	if _, err = c.Write(req); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 4)
	if _, err = io.ReadFull(c, head); err != nil || head[1] != 0 {
		t.Fatalf("SOCKS connect: %v %v", head, err)
	}
	n := 6
	if head[3] == 3 {
		one := make([]byte, 1)
		if _, err = io.ReadFull(c, one); err != nil {
			t.Fatal(err)
		}
		n = int(one[0]) + 2
	} else if head[3] == 4 {
		n = 18
	}
	if _, err = io.ReadFull(c, make([]byte, n)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("lattice-linechain-e2e")
	if _, err = c.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 0, 128)
	buf := make([]byte, 32)
	for len(got) < cap(got) && !bytes.Contains(got, payload) {
		n, readErr := c.Read(buf)
		got = append(got, buf[:n]...)
		if readErr != nil {
			err = readErr
			break
		}
	}
	if !bytes.Contains(got, payload) {
		t.Fatalf("chain echo = %q err=%v", got, err)
	}
}
