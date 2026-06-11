package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-node-agent/internal/metrics"
	"github.com/LatticeNet/lattice-node-agent/internal/taskexec"
	"github.com/LatticeNet/lattice-sdk/model"
)

const version = "0.1.0"

// httpClient bounds every agent request so a hung or black-holed server cannot
// wedge the agent's poll loop indefinitely. The total timeout comfortably
// exceeds task execution because task results are posted separately.
var httpClient = &http.Client{Timeout: 30 * time.Second}

type agentConfig struct {
	Server      string
	NodeID      string
	Token       string
	Interval    time.Duration
	AllowExec   bool
	PublicIP    string
	WireGuardIP string
}

func main() {
	var cfg agentConfig
	flag.StringVar(&cfg.Server, "server", env("LATTICE_SERVER", "http://127.0.0.1:8088"), "server base URL")
	flag.StringVar(&cfg.NodeID, "node-id", os.Getenv("LATTICE_NODE_ID"), "node id")
	flag.StringVar(&cfg.Token, "token", os.Getenv("LATTICE_NODE_TOKEN"), "node enrollment token")
	flag.DurationVar(&cfg.Interval, "interval", 10*time.Second, "metrics interval")
	flag.BoolVar(&cfg.AllowExec, "allow-exec", os.Getenv("LATTICE_AGENT_ALLOW_EXEC") == "1", "allow bounded task execution")
	flag.StringVar(&cfg.PublicIP, "public-ip", os.Getenv("LATTICE_PUBLIC_IP"), "public IP metadata")
	flag.StringVar(&cfg.WireGuardIP, "wg-ip", os.Getenv("LATTICE_WG_IP"), "WireGuard IP metadata")
	flag.Parse()
	if cfg.NodeID == "" || cfg.Token == "" {
		log.Fatal("node-id and token are required")
	}
	cfg.Server = strings.TrimRight(cfg.Server, "/")
	if err := postJSON(cfg.Server+"/api/agent/hello", map[string]any{
		"node_id":      cfg.NodeID,
		"token":        cfg.Token,
		"version":      version,
		"public_ip":    cfg.PublicIP,
		"wireguard_ip": cfg.WireGuardIP,
	}, nil); err != nil {
		log.Fatalf("hello failed: %v", err)
	}
	log.Printf("lattice-agent connected node=%s server=%s allow_exec=%v", cfg.NodeID, cfg.Server, cfg.AllowExec)

	runner := taskexec.Runner{AllowExec: cfg.AllowExec}
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		if err := reportMetrics(cfg); err != nil {
			log.Printf("metrics error: %v", err)
		}
		if err := runTasks(cfg, runner); err != nil {
			log.Printf("task poll error: %v", err)
		}
		<-ticker.C
	}
}

func reportMetrics(cfg agentConfig) error {
	return postJSON(cfg.Server+"/api/agent/metrics", map[string]any{
		"node_id":      cfg.NodeID,
		"token":        cfg.Token,
		"version":      version,
		"public_ip":    cfg.PublicIP,
		"wireguard_ip": cfg.WireGuardIP,
		"metrics":      metrics.Collect(),
	}, nil)
}

func runTasks(cfg agentConfig, runner taskexec.Runner) error {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/agent/tasks?node_id=%s", cfg.Server, cfg.NodeID), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %s", resp.Status)
	}
	var tasks []model.Task
	if err := json.NewDecoder(resp.Body).Decode(&tasks); err != nil {
		return err
	}
	for _, task := range tasks {
		result := runner.Run(task)
		result.NodeID = cfg.NodeID
		if err := postJSON(cfg.Server+"/api/agent/task-result", map[string]any{
			"node_id": cfg.NodeID,
			"token":   cfg.Token,
			"result":  result,
		}, nil); err != nil {
			return err
		}
	}
	return nil
}

func postJSON(url string, payload any, out any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("server returned %s", resp.Status)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
