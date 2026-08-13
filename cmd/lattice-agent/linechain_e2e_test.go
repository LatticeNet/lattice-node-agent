package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/linechain"
)

// TestLinechainRealSingBoxE2E is invoked by scripts/test-linechain-e2e.sh.
// Normal unit runs leave the real-binary lane to that mandatory harness.
func TestLinechainRealSingBoxE2E(t *testing.T) {
	bin := os.Getenv("LATTICE_SINGBOX_E2E_BIN")
	if bin == "" {
		return
	}
	root := t.TempDir()
	origin := startEchoOrigin(t)
	aPort, bPort, clientPort := freePort(t), freePort(t), freePort(t)
	const uuidA = "11111111-1111-4111-8111-111111111111"
	const uuidB = "22222222-2222-4222-8222-222222222222"
	aConfig := fmt.Sprintf(`{"log":{"level":"error"},"inbounds":[{"type":"vless","tag":"target-a","listen":"127.0.0.1","listen_port":%d,"users":[{"uuid":"%s"}]}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`, aPort, uuidA)
	bConfig := fmt.Sprintf(`{"log":{"level":"error"},"inbounds":[{"type":"vless","tag":"source-b","listen":"127.0.0.1","listen_port":%d,"users":[{"uuid":"%s"}]}],"outbounds":[{"type":"vless","tag":"chain-to-a","server":"127.0.0.1","server_port":%d,"uuid":"%s"}],"route":{"final":"chain-to-a"}}`, bPort, uuidB, aPort, uuidA)
	clientConfig := fmt.Sprintf(`{"log":{"level":"error"},"inbounds":[{"type":"socks","tag":"client","listen":"127.0.0.1","listen_port":%d}],"outbounds":[{"type":"vless","tag":"to-b","server":"127.0.0.1","server_port":%d,"uuid":"%s"}],"route":{"final":"to-b"}}`, clientPort, bPort, uuidB)
	startSingBox(t, bin, root, "a", aConfig, aPort)
	startSingBox(t, bin, root, "b", bConfig, bPort)
	startSingBox(t, bin, root, "client", clientConfig, clientPort)
	assertSOCKSEcho(t, clientPort, origin)

	conf := filepath.Join(root, "conf")
	if err := os.Mkdir(conf, 0o700); err != nil {
		t.Fatal(err)
	}
	fragmentPath := filepath.Join(conf, "lattice-linechain-e2e.json")
	sidecarPath := filepath.Join(root, "lattice-metadata.json")
	fragment := "{\n  \"outbounds\": [{\"type\": \"direct\", \"tag\": \"linechain-direct\"}]\n}\n"
	sidecar := "{\"schema\":\"lattice.singbox-metadata.v2\",\"inbounds\":[]}\n"
	doc := linechain.Document{Version: 1, ConfigDir: conf, FragmentPath: fragmentPath, SidecarPath: sidecarPath, Fragment: &fragment, Sidecar: &sidecar, SingBoxBinary: bin, CheckArgs: []string{"check", "-C", conf}, RestartCommand: []string{"true"}, VerifyCommand: []string{"true"}}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	m, err := linechain.Open(filepath.Join(root, "txn"))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Apply(context.Background(), bytes.NewReader(b), "e2e-task", "e2e-lease"); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(fragmentPath); err != nil || string(got) != fragment {
		t.Fatalf("fragment mismatch: %q %v", got, err)
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

func startSingBox(t *testing.T, bin, root, name, config string, port int) {
	t.Helper()
	path := filepath.Join(root, name+".json")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "run", "-c", path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("sing-box %s did not listen: %s", name, stderr.String())
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
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("chain echo = %q err=%v", got, err)
	}
}
