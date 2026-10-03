package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/LatticeNet/lattice-node-agent/internal/witness"
)

// Control-plane witness, the agent side.
//
// `lattice-agent -witness <config>` runs internal/witness as its own process
// under its own unit (lattice-witness.service, written by an approved plan).
// The agent's own loop only relays the witness's status file on its
// heartbeat, so the console can show when the witness last checked and last
// pushed. The relay reads a file and nothing else; it never starts, stops or
// configures the witness.

// witnessStatusEnv overrides where the agent looks for the witness status.
const witnessStatusEnv = "LATTICE_WITNESS_STATUS_FILE"

// runWitnessMode runs or checks the witness. With check it validates the
// config and the key file and prints what it would watch, never the key.
func runWitnessMode(configPath string, check bool, out io.Writer) error {
	if strings.TrimSpace(configPath) == "" {
		return errors.New("-witness needs the path of the witness config")
	}
	if check {
		cfg, sha, err := witness.LoadConfig(configPath)
		if err != nil {
			return err
		}
		if _, err := witness.ReadDeviceKey(cfg.BarkDeviceKeyFile); err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "witness config ok: sha256=%s node=%q health=%s references=%d bark=%s key_file=%s interval=%s hold=%s recover=%s state=%s\n",
			sha, cfg.NodeName, cfg.HealthURL, len(cfg.ReferenceURLs), cfg.BarkURL, cfg.BarkDeviceKeyFile, cfg.Interval(), cfg.Hold(), cfg.Recover(), cfg.State())
		return err
	}
	w, err := witness.Start(configPath)
	if err != nil {
		return err
	}
	st := w.State()
	log.Printf("witness started: health=%s references=%d interval=%ds hold=%ds phase=%s alerted=%v", st.HealthURL, st.ReferenceCount, st.IntervalSeconds, st.HoldSeconds, st.Phase, st.Alerted)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	w.Run(ctx)
	log.Printf("witness stopped")
	return nil
}

// witnessStatusPath is where the heartbeat looks for the witness status.
func witnessStatusPath() string {
	if p := strings.TrimSpace(os.Getenv(witnessStatusEnv)); p != "" {
		return p
	}
	return witness.DefaultStateFile
}

// maxWitnessStatusBytes bounds the status read on every heartbeat.
const maxWitnessStatusBytes = 16 << 10

// readWitnessStatus returns the witness status for the heartbeat, or nil
// when this node runs no witness. The document is re-encoded from its typed
// form, so only the fields the witness defines leave the node.
func readWitnessStatus(path string) *witness.State {
	raw, err := witness.ReadBounded(path, maxWitnessStatusBytes)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			debugOnce("witness status unreadable: " + err.Error())
		}
		return nil
	}
	var st witness.State
	if err := json.Unmarshal(raw, &st); err != nil || st.Version == 0 {
		debugOnce("witness status is not a witness state document")
		return nil
	}
	return &st
}

// debugOnce logs a relay problem once per distinct message, so a broken file
// does not fill the journal at every beat.
var (
	witnessRelayMu     sync.Mutex
	witnessRelayLogged = map[string]bool{}
)

func debugOnce(msg string) {
	witnessRelayMu.Lock()
	defer witnessRelayMu.Unlock()
	if witnessRelayLogged[msg] {
		return
	}
	witnessRelayLogged[msg] = true
	log.Printf("%s", msg)
}
