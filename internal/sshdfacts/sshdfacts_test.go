package sshdfacts

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

// The testdata files are real `sshd -T` renderings (OpenSSH 9.9p2, run with
// -f against a Debian 12 style sshd_config and a hardened one). Debian 12
// ships OpenSSH 9.2p1, which prints the same key/value lines for everything
// this parser reads; only the host key path was rewritten to the Debian
// default because the capture had to run without root.
func readSample(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseDebian12Default(t *testing.T) {
	got, err := Parse(readSample(t, "debian12-default.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want := model.GuardSSHDFacts{
		PasswordAuthentication: true,
		PubkeyAuthentication:   true,
		PermitRootLogin:        "prohibit-password",
		MaxAuthTries:           6,
		Ports:                  []int{22},
		ListenAddresses:        []string{"0.0.0.0:22", "[::]:22"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed facts:\n got %+v\nwant %+v", got, want)
	}
}

func TestParseHardenedSample(t *testing.T) {
	got, err := Parse(readSample(t, "hardened-58394.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want := model.GuardSSHDFacts{
		PasswordAuthentication: false,
		PubkeyAuthentication:   true,
		PermitRootLogin:        "no",
		MaxAuthTries:           3,
		// sshd prints ports in configuration order (58394 first); the report
		// sorts them so two identical configurations compare equal.
		Ports:           []int{22, 58394},
		ListenAddresses: []string{"203.0.113.7:58394"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed facts:\n got %+v\nwant %+v", got, want)
	}
}

func TestParseToleratesNoiseAndDuplicates(t *testing.T) {
	raw := "\r\nPort 22\r\nport 22\nsomefuturekey with several words\n\tListenAddress   [::]:22  \nlistenaddress [::]:22\npasswordauthentication NO\nPubkeyAuthentication yes\npermitrootlogin forced-commands-only\n"
	got, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	want := model.GuardSSHDFacts{
		PermitRootLogin:      "forced-commands-only",
		PubkeyAuthentication: true,
		Ports:                []int{22},
		ListenAddresses:      []string{"[::]:22"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed facts:\n got %+v\nwant %+v", got, want)
	}
}

func TestParseRefusesToGuessMissingOrBrokenFacts(t *testing.T) {
	base := "port 22\npasswordauthentication yes\npubkeyauthentication yes\npermitrootlogin yes\n"
	cases := map[string]string{
		"no password line": strings.Replace(base, "passwordauthentication yes\n", "", 1),
		"no pubkey line":   strings.Replace(base, "pubkeyauthentication yes\n", "", 1),
		"no root line":     strings.Replace(base, "permitrootlogin yes\n", "", 1),
		"no port line":     strings.Replace(base, "port 22\n", "", 1),
		"bad bool":         strings.Replace(base, "passwordauthentication yes", "passwordauthentication maybe", 1),
		"bad port":         strings.Replace(base, "port 22", "port 70000", 1),
		"bad tries":        base + "maxauthtries lots\n",
		"empty":            "",
	}
	for name, raw := range cases {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: Parse accepted %q", name, raw)
		}
	}
}

func TestCollectRefusesWithoutRoot(t *testing.T) {
	facts, note := Collect(context.Background(), Source{
		EUID:    func() int { return 1000 },
		Resolve: func(string) (string, string) { t.Fatal("resolve must not run without root"); return "", "" },
		Runner: func(context.Context, string, ...string) ([]byte, error) {
			t.Fatal("runner must not run without root")
			return nil, nil
		},
	})
	if facts != nil || !strings.Contains(note, "root") || !strings.Contains(note, "uid 1000") {
		t.Fatalf("facts=%+v note=%q", facts, note)
	}
}

func TestCollectRefusesUntrustedSSHD(t *testing.T) {
	facts, note := Collect(context.Background(), Source{
		EUID: func() int { return 0 },
		Resolve: func(name string) (string, string) {
			return "", name + " not found in the trusted executable directories (/usr/sbin)"
		},
		Runner: func(context.Context, string, ...string) ([]byte, error) {
			t.Fatal("runner must not run for a refused sshd")
			return nil, nil
		},
	})
	if facts != nil || note != "sshd not found in the trusted executable directories (/usr/sbin)" {
		t.Fatalf("facts=%+v note=%q", facts, note)
	}
}

func TestCollectReportsCommandAndParseFailures(t *testing.T) {
	src := Source{
		EUID:    func() int { return 0 },
		Resolve: func(string) (string, string) { return "/usr/sbin/sshd", "" },
		Runner: func(context.Context, string, ...string) ([]byte, error) {
			return nil, errors.New("exit status 255: sshd: no hostkeys available")
		},
	}
	facts, note := Collect(context.Background(), src)
	if facts != nil || !strings.HasPrefix(note, "/usr/sbin/sshd -T: ") || !strings.Contains(note, "no hostkeys") {
		t.Fatalf("command failure: facts=%+v note=%q", facts, note)
	}
	src.Runner = func(context.Context, string, ...string) ([]byte, error) { return []byte("port 22\n"), nil }
	facts, note = Collect(context.Background(), src)
	if facts != nil || !strings.Contains(note, "no passwordauthentication line") {
		t.Fatalf("parse failure: facts=%+v note=%q", facts, note)
	}
}

func TestCollectRunsTrustedSSHDUnderDeadline(t *testing.T) {
	observed := time.Date(2026, time.September, 2, 7, 0, 0, 0, time.UTC)
	var gotName string
	var gotArgs []string
	var hadDeadline bool
	facts, note := Collect(context.Background(), Source{
		EUID:    func() int { return 0 },
		Resolve: func(string) (string, string) { return "/usr/sbin/sshd", "" },
		Now:     func() time.Time { return observed },
		Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			gotName, gotArgs = name, args
			deadline, ok := ctx.Deadline()
			hadDeadline = ok && time.Until(deadline) <= defaultTimeout
			return readSample(t, "hardened-58394.txt"), nil
		},
	})
	if note != "" || facts == nil {
		t.Fatalf("facts=%+v note=%q", facts, note)
	}
	if gotName != "/usr/sbin/sshd" || !reflect.DeepEqual(gotArgs, []string{"-T"}) {
		t.Fatalf("ran %s %v, want /usr/sbin/sshd [-T]", gotName, gotArgs)
	}
	if !hadDeadline {
		t.Fatal("sshd -T ran without the 3 second deadline")
	}
	if facts.PasswordAuthentication || !reflect.DeepEqual(facts.Ports, []int{22, 58394}) || !facts.ObservedAt.Equal(observed) {
		t.Fatalf("facts=%+v", facts)
	}
}
