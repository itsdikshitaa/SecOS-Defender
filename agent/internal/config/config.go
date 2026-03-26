package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

type TLSConfig struct {
	CAFile   string `json:"ca_file"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

type Config struct {
	APIBaseURL              string    `json:"api_base_url"`
	HostID                  string    `json:"host_id"`
	Hostname                string    `json:"hostname"`
	Platform                string    `json:"platform"`
	AgentVersion            string    `json:"agent_version"`
	QueueFile               string    `json:"queue_file"`
	CollectIntervalSeconds  int       `json:"collect_interval_seconds"`
	HeartbeatIntervalSeconds int      `json:"heartbeat_interval_seconds"`
	InventoryIntervalSeconds int      `json:"inventory_interval_seconds"`
	FixtureEventsPath       string    `json:"fixture_events_path"`
	FixtureInventoryPath    string    `json:"fixture_inventory_path"`
	TLS                     TLSConfig `json:"tls"`
}

func Load(path string) (Config, error) {
	cfg := Config{
		APIBaseURL:               "http://localhost:8000",
		AgentVersion:             "2.0.0-dev",
		QueueFile:                filepath.Join("agent", "data", "queue.json"),
		CollectIntervalSeconds:   30,
		HeartbeatIntervalSeconds: 15,
		InventoryIntervalSeconds: 300,
		Platform:                 runtime.GOOS,
	}

	hostname, _ := os.Hostname()
	cfg.Hostname = hostname
	cfg.HostID = hostname

	if path == "" {
		return cfg, nil
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}

	if err := json.Unmarshal(contents, &cfg); err != nil {
		return cfg, err
	}

	if cfg.Platform == "" {
		cfg.Platform = runtime.GOOS
	}
	if cfg.HostID == "" {
		cfg.HostID = cfg.Hostname
	}
	if cfg.QueueFile == "" {
		cfg.QueueFile = filepath.Join("agent", "data", "queue.json")
	}
	return cfg, nil
}
