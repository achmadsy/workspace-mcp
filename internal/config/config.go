// Package config loads and validates immutable process configuration.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Mode string

const (
	ModeLocal  Mode = "local"
	ModePublic Mode = "public"
)

type Config struct {
	WorkspaceRoot string
	Host          string
	Port          int
	Mode          Mode
	PublicURL     string
	AdminPassword string
	StateDir      string
	StateKey      [32]byte
	TrustTunnel   bool
}

func Load() (Config, error) {
	var c Config
	c.WorkspaceRoot = strings.TrimSpace(os.Getenv("WORKSPACE_ROOT"))
	c.Host = envDefault("MCP_HOST", "127.0.0.1")
	c.Mode = Mode(envDefault("MCP_MODE", "local"))
	c.PublicURL = strings.TrimSpace(os.Getenv("MCP_PUBLIC_URL"))
	c.AdminPassword = os.Getenv("MCP_ADMIN_PASSWORD")
	c.StateDir = strings.TrimSpace(os.Getenv("MCP_STATE_DIR"))
	c.TrustTunnel = envBool("MCP_TRUST_CLOUDFLARE_TUNNEL")
	port, err := strconv.Atoi(envDefault("MCP_PORT", "8787"))
	if err != nil || port < 1 || port > 65535 {
		return Config{}, errors.New("MCP_PORT must be an integer from 1 to 65535")
	}
	c.Port = port
	if c.WorkspaceRoot == "" || !filepath.IsAbs(c.WorkspaceRoot) {
		return Config{}, errors.New("WORKSPACE_ROOT must be an absolute path")
	}
	c.WorkspaceRoot = filepath.Clean(c.WorkspaceRoot)
	st, err := os.Stat(c.WorkspaceRoot)
	if err != nil || !st.IsDir() {
		return Config{}, errors.New("WORKSPACE_ROOT must identify an existing directory")
	}
	if c.Host == "" || net.ParseIP(c.Host) == nil {
		return Config{}, errors.New("MCP_HOST must be an IP address")
	}
	if c.Mode != ModeLocal && c.Mode != ModePublic {
		return Config{}, errors.New("MCP_MODE must be local or public")
	}
	if c.Mode == ModeLocal {
		if !isLoopback(c.Host) {
			return Config{}, errors.New("local mode requires a loopback MCP_HOST")
		}
		return c, nil
	}
	if !isLoopback(c.Host) {
		return Config{}, errors.New("public mode requires loopback MCP_HOST; Cloudflare Tunnel connects locally")
	}
	if c.PublicURL == "" {
		return Config{}, errors.New("MCP_PUBLIC_URL is required in public mode")
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "/mcp" || u.RawQuery != "" || u.Fragment != "" {
		return Config{}, errors.New("MCP_PUBLIC_URL must be an exact HTTPS URL ending in /mcp")
	}
	if len(c.AdminPassword) < 12 {
		return Config{}, errors.New("MCP_ADMIN_PASSWORD must be at least 12 characters in public mode")
	}
	if c.StateDir == "" || !filepath.IsAbs(c.StateDir) {
		return Config{}, errors.New("MCP_STATE_DIR must be an absolute path in public mode")
	}
	key, err := base64.StdEncoding.DecodeString(os.Getenv("MCP_STATE_KEY"))
	if err != nil || len(key) != 32 {
		return Config{}, errors.New("MCP_STATE_KEY must be base64 encoding of exactly 32 random bytes")
	}
	copy(c.StateKey[:], key)
	return c, nil
}

func (c Config) Address() string { return net.JoinHostPort(c.Host, strconv.Itoa(c.Port)) }
func (c Config) Origin() string {
	if c.PublicURL == "" {
		return fmt.Sprintf("http://%s", c.Address())
	}
	return strings.TrimSuffix(c.PublicURL, "/mcp")
}

func envDefault(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}
func envBool(k string) bool       { v, _ := strconv.ParseBool(strings.TrimSpace(os.Getenv(k))); return v }
func isLoopback(host string) bool { ip := net.ParseIP(host); return ip != nil && ip.IsLoopback() }
