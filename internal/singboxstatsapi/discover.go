// Package singboxstatsapi finds the loopback address of sing-box's
// experimental V2Ray stats API in the on-box config, so a node whose sb
// manager turned stats on reports usage without a separate agent flag.
package singboxstatsapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/LatticeNet/lattice-node-agent/internal/proxyusage"
	"github.com/LatticeNet/lattice-node-agent/internal/singboxdiscover"
)

const (
	defaultConfigFile = "/etc/sing-box/config.json"
	defaultConfigDir  = "/etc/sing-box/conf"
	// maxConfigBytes matches the discoverer's ceiling, so the file that
	// discovery accepts is accepted here too and an oversized file cannot
	// take the agent down with the disk on every interval.
	maxConfigBytes = 8 << 20
)

// Result names where the stats API listens and which file declared it.
type Result struct {
	Addr string
	Path string
}

// ConfigFiles lists the sing-box config files the agent treats as authority:
// the -c/-C arguments of the trusted running processes, then the conventional
// /etc/sing-box/config.json and /etc/sing-box/conf/*.json. Process selection
// is the discoverer's trust boundary (root process, trusted executable); the
// argument walk mirrors the discoverer's own, which is not exported. Fold the
// two into one exported helper once that package is free to change.
func ConfigFiles() []string {
	return configFiles(singboxdiscover.TrustedProcesses(), defaultConfigFile, defaultConfigDir)
}

func configFiles(processes []singboxdiscover.TrustedProcess, defaultFile, defaultDir string) []string {
	seen := map[string]bool{}
	var out []string
	addFile := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" || !filepath.IsAbs(path) {
			return
		}
		clean := filepath.Clean(path)
		if seen[clean] {
			return
		}
		if st, err := os.Stat(clean); err == nil && !st.IsDir() {
			seen[clean] = true
			out = append(out, clean)
		}
	}
	addDir := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" || !filepath.IsAbs(path) {
			return
		}
		matches, _ := filepath.Glob(filepath.Join(filepath.Clean(path), "*.json"))
		sort.Strings(matches)
		for _, match := range matches {
			addFile(match)
		}
	}
	for _, proc := range processes {
		args := proc.Args
		for i := 0; i < len(args); i++ {
			switch arg := args[i]; arg {
			case "-c", "--config":
				if i+1 < len(args) {
					i++
					addFile(args[i])
				}
			case "-C", "--config-directory":
				if i+1 < len(args) {
					i++
					addDir(args[i])
				}
			default:
				for _, prefix := range []string{"-c=", "--config="} {
					if value, ok := strings.CutPrefix(arg, prefix); ok {
						addFile(value)
					}
				}
				for _, prefix := range []string{"-C=", "--config-directory="} {
					if value, ok := strings.CutPrefix(arg, prefix); ok {
						addDir(value)
					}
				}
			}
		}
	}
	addFile(defaultFile)
	addDir(defaultDir)
	return out
}

// Discover reads the given config files in order and returns the first
// experimental.v2ray_api.listen it finds. A file that does not read or decode
// is skipped: discovery is best-effort and the discoverer already logs
// undecodable configs. An empty Result means no file declares a listen. A
// declared listen that is not loopback host:port is an error naming the file,
// because using it would let a config file point the agent off-host, which
// is exactly what the -singbox-stats-api flag refuses.
func Discover(files []string) (Result, error) {
	for _, path := range files {
		raw, err := readBounded(path)
		if err != nil {
			continue
		}
		var cfg struct {
			Experimental struct {
				V2RayAPI struct {
					Listen string `json:"listen"`
				} `json:"v2ray_api"`
			} `json:"experimental"`
		}
		if err := json.Unmarshal(bytes.TrimSpace(raw), &cfg); err != nil {
			continue
		}
		listen := strings.TrimSpace(cfg.Experimental.V2RayAPI.Listen)
		if listen == "" {
			continue
		}
		if err := proxyusage.ValidateSingBoxStatsSource(proxyusage.SingBoxStatsSource{APIAddr: listen}); err != nil {
			return Result{Path: path}, fmt.Errorf("%s declares experimental.v2ray_api.listen %q: %w", path, listen, err)
		}
		return Result{Addr: listen, Path: path}, nil
	}
	return Result{}, nil
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfigBytes {
		return nil, fmt.Errorf("sing-box config %s exceeds %d bytes", path, maxConfigBytes)
	}
	return data, nil
}
