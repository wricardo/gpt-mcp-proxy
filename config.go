package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

// MCPServerConfig represents the configuration for an MCP server.
type MCPServerConfig struct {
	Command     string            `json:"command"`
	Args        []string          `json:"args"`
	Env         map[string]string `json:"env"`
	Disabled    bool              `json:"disabled"`
	AutoApprove []string          `json:"autoApprove"`
	Timeout     int               `json:"timeout,omitempty"`
}

// AppConfig represents the overall configuration for the application.
type AppConfig struct {
	MCPServers map[string]MCPServerConfig `json:"mcpServers"`
}

// LoadConfig reads the configuration from a file and returns an AppConfig struct.
func LoadConfig(filename string) (*AppConfig, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var config AppConfig
	if err := json.Unmarshal(bytes, &config); err != nil {
		return nil, err
	}

	return &config, nil
}
