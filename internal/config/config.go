// Package config handles the .proofctl project directory and config file.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	DirName    = ".proofctl"
	ConfigFile = "config.json"
	CASDir     = "cas"
	GraphFile  = "graph.json"
	AttestDir  = "attestations"
	StatusFile = "STATUS.json"
)

// ProjectConfig is the .proofctl/config.json structure.
type ProjectConfig struct {
	Version     string `json:"version"`
	PolicyFile  string `json:"policy_file"`
	GraphSource string `json:"graph_source"`
}

// Find walks up from dir looking for a .proofctl directory.
// Returns the project root (the dir containing .proofctl) or error.
func Find(dir string) (string, error) {
	for {
		if _, err := os.Stat(filepath.Join(dir, DirName)); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("config: no .proofctl directory found")
		}
		dir = parent
	}
}

// Load reads and parses .proofctl/config.json from the given project root.
func Load(root string) (*ProjectConfig, error) {
	path := filepath.Join(root, DirName, ConfigFile)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: open: %w", err)
	}
	defer func() { _ = f.Close() }()
	var cfg ProjectConfig
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config: decode: %w", err)
	}
	return &cfg, nil
}

// Init creates the .proofctl directory structure in root.
// policyFile is written as-is into config.json; pass an empty string if unknown.
// Returns error if .proofctl already exists.
func Init(root string, policyFile string) error {
	proofDir := filepath.Join(root, DirName)
	if _, err := os.Stat(proofDir); err == nil {
		return fmt.Errorf("config: .proofctl already exists in %s", root)
	}
	for _, dir := range []string{proofDir, filepath.Join(proofDir, CASDir), filepath.Join(proofDir, AttestDir)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("config: mkdir %s: %w", dir, err)
		}
	}
	cfg := ProjectConfig{
		Version:     "1",
		PolicyFile:  policyFile,
		GraphSource: "graph.json",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	data = append(data, '\n')
	cfgPath := filepath.Join(proofDir, ConfigFile)
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		return fmt.Errorf("config: write config: %w", err)
	}
	return nil
}
