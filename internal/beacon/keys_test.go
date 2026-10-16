package beacon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	wire "github.com/LatticeNet/lattice-sdk/beacon"
	"github.com/LatticeNet/lattice-sdk/model"
)

// keyForms are the ways a key could show up in text: raw, base64 in every
// alphabet, hex in either case, and Go's formatting of the byte values.
func keyForms(k []byte) []string {
	head := k[:12]
	return []string{
		string(k),
		base64.StdEncoding.EncodeToString(k),
		base64.RawStdEncoding.EncodeToString(k),
		base64.URLEncoding.EncodeToString(k),
		base64.RawURLEncoding.EncodeToString(head),
		base64.StdEncoding.EncodeToString(head)[:12],
		hex.EncodeToString(head),
		strings.ToUpper(hex.EncodeToString(head)),
		strings.Trim(fmt.Sprint(head), "[]"),
		strings.TrimSuffix(strings.TrimPrefix(fmt.Sprintf("%#v", head), "[]byte{"), "}"),
		strings.Trim(fmt.Sprintf("%q", head), `"`),
	}
}

func assertNoKey(t *testing.T, where, text string, keys ...wire.Key) {
	t.Helper()
	for _, k := range keys {
		for _, form := range keyForms(k[:]) {
			if form != "" && strings.Contains(text, form) {
				t.Fatalf("%s carries key material %q", where, form)
			}
		}
	}
}

// Keys reach nodes only through the config pull and stay in memory: no log
// line, fact, error, formatted value or result carries one, whatever path
// the beacon takes (listening, a bind failure, a refused table, the client
// with and without a key).
func TestKeysNeverReachLogsFactsOrResults(t *testing.T) {
	var logged bytes.Buffer
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(&logged)
	defer func() { log.SetOutput(prev); log.SetFlags(flags) }()

	target := targetKey()
	path := pathKeyFor(testSource, testEpoch)
	var texts []string

	node := NewNode(false)
	l := &loopbackListener{}
	node.responder.listen = l.listen
	node.client.spacing = 0
	cfg := &model.AgentBeaconConfig{
		SourceID:  testSource,
		Keys:      []model.BeaconPathKey{{TargetNode: "t1", Epoch: testEpoch, Key: append([]byte(nil), path[:]...)}},
		Responder: responderConfig(freeUDPPort(t)),
	}
	node.Apply(cfg)
	t.Cleanup(node.Close)
	local := l.localAddr(t)
	node.client.dial = func(ctx context.Context, _ netip.AddrPort) (clientConn, error) { return dialUDP4(ctx, local) }
	res := node.Probe(context.Background(), beaconCheck(2))
	if !res.Success {
		t.Fatalf("probe %+v", res)
	}
	texts = append(texts, fmt.Sprintf("%+v", res))
	noKey := beaconCheck(1)
	noKey.TargetNode = "t9"
	texts = append(texts, fmt.Sprintf("%+v", node.Probe(context.Background(), noKey)))

	// A refused table and a refused bind.
	bad := responderConfig(45000)
	bad.Table[0].Key = append(bad.Table[0].Key, target[:]...)
	node.responder.Apply(bad)
	texts = append(texts, node.Facts().Error)
	wild := responderConfig(45000)
	wild.Bind = "0.0.0.0"
	node.responder.Apply(wild)
	texts = append(texts, node.Facts().Error)

	facts, err := json.Marshal(node.Facts())
	if err != nil {
		t.Fatal(err)
	}
	texts = append(texts, string(facts),
		fmt.Sprintf("%v", node), fmt.Sprintf("%+v", node), fmt.Sprintf("%#v", node), fmt.Sprintf("%s", node),
		fmt.Sprintf("%v", node.keys), fmt.Sprintf("%#v", node.keys), logged.String())
	for i, text := range texts {
		assertNoKey(t, fmt.Sprintf("text %d", i), text, target, path)
	}
	for i, e := range cfg.Keys {
		if !bytes.Equal(e.Key, make([]byte, len(e.Key))) {
			t.Fatalf("source key %d left in the decoded config", i)
		}
	}
	for i, e := range cfg.Responder.Table {
		if !bytes.Equal(e.Key, make([]byte, len(e.Key))) {
			t.Fatalf("table key %d left in the decoded config", i)
		}
	}
}

// Nothing in the package writes a file: no os call that creates, opens for
// writing, renames or changes a file, and no ioutil.
func TestPackageWritesNoFiles(t *testing.T) {
	forbidden := map[string]bool{
		"Create": true, "CreateTemp": true, "WriteFile": true, "OpenFile": true, "Mkdir": true,
		"MkdirAll": true, "MkdirTemp": true, "Rename": true, "Symlink": true, "Link": true,
		"Chmod": true, "Chown": true, "Truncate": true, "NewFile": true,
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, imp := range f.Imports {
			if p := strings.Trim(imp.Path.Value, `"`); p == "io/ioutil" || p == "os/exec" {
				t.Fatalf("%s imports %s", name, p)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "os" && forbidden[sel.Sel.Name] {
				t.Fatalf("%s: os.%s at %s", name, sel.Sel.Name, fset.Position(sel.Pos()))
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no source checked")
	}
	if _, err := os.Stat("responder.go"); err != nil {
		t.Fatal(err)
	}
}

// The search above finds a key however a careless log line would print it.
func TestKeyFormsCatchAPlantedKey(t *testing.T) {
	k := pathKeyFor(testSource, testEpoch)
	for _, planted := range []string{
		fmt.Sprintf("key=%x", k[:]), fmt.Sprintf("key=%X", k[:]), fmt.Sprintf("key=%v", k), fmt.Sprintf("key=%v", k[:]),
		fmt.Sprintf("key=%#v", k[:]), "key=" + base64.StdEncoding.EncodeToString(k[:]), fmt.Sprintf("%+v", model.BeaconPathKey{Key: k[:]}),
		fmt.Sprintf("%s", k[:]), fmt.Sprintf("%q", k[:]),
	} {
		found := false
		for _, form := range keyForms(k[:]) {
			if form != "" && strings.Contains(planted, form) {
				found = true
			}
		}
		if !found && !strings.Contains(planted, string(k[:4])) {
			t.Fatalf("a planted key went unnoticed: %q", planted)
		}
	}
}
