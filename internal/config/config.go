// Package config loads and validates immutable process configuration.
package config

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/link/workspace-mcp/internal/limits"
)

type Mode string

const (
	ModeLocal  Mode = "local"
	ModePublic Mode = "public"
)

type Config struct {
	WorkspaceRoot  string
	Host           string
	Port           int
	Mode           Mode
	PublicURL      string
	AdminPassword  string
	StateDir       string
	StateKey       [32]byte
	TrustTunnel    bool
	AllowedOrigins []string

	EnableExec       bool
	EnableGitWrite   bool
	EnableGitNetwork bool
	BwrapPath        string
	Slirp4netnsPath  string
	SystemdRunPath   string
	PrlimitPath      string
	ExecTimeout      time.Duration
	ExecJobTimeout   time.Duration
	ExecJobTTL       time.Duration
	ExecMaxOutput    int
	ExecMaxJobs      int
	ExecMemoryBytes  uint64
	ExecCPUSeconds   uint64
	ExecMaxProcesses uint64
	ExecMaxOpenFiles uint64
	// ExecMaxFileBytes bounds the size of any single file a sandboxed command may
	// create (RLIMIT_FSIZE). It is independent of ExecMaxOutput.
	ExecMaxFileBytes uint64
	// ExecDisableUserns prevents sandboxed code from creating nested user
	// namespaces. It is requested via MCP_EXEC_DISABLE_USERNS and downgraded at
	// startup when the installed bubblewrap does not support it.
	ExecDisableUserns bool
	// SlirpSandbox and SlirpSeccomp harden the slirp4netns helper. They are
	// requested via MCP_SLIRP_HARDENING and downgraded when unsupported.
	SlirpSandbox bool
	SlirpSeccomp bool
	// SystemctlPath is optional; when present it is used as a best-effort
	// fallback to kill a sandbox scope after timeout or cancellation.
	SystemctlPath string

	GitCredentialMode string
	GitCredentialFile string
	GitKnownHostsFile string
	GitAllowedRemotes []string
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
	c.EnableExec = envBool("MCP_ENABLE_EXEC")
	c.EnableGitWrite = envBool("MCP_ENABLE_GIT_WRITE")
	c.EnableGitNetwork = envBool("MCP_ENABLE_GIT_NETWORK")
	c.ExecTimeout = envDuration("MCP_EXEC_TIMEOUT", limits.ExecTimeout)
	c.ExecJobTimeout = envDuration("MCP_EXEC_JOB_TIMEOUT", limits.ExecJobTimeout)
	c.ExecJobTTL = envDuration("MCP_EXEC_JOB_TTL", limits.ExecJobTTL)
	c.ExecMaxOutput = envInt("MCP_EXEC_MAX_OUTPUT", limits.MaxExecOutput)
	c.ExecMaxJobs = envInt("MCP_EXEC_MAX_JOBS", limits.MaxExecJobs)
	c.ExecMemoryBytes = uint64(envInt64("MCP_EXEC_MEMORY_BYTES", 2<<30))
	c.ExecCPUSeconds = uint64(envInt64("MCP_EXEC_CPU_SECONDS", 300))
	// RLIMIT_NPROC is per real UID and would also count the server itself, so the
	// process bound is enforced per sandbox through the cgroup TasksMax instead.
	// TasksMax counts threads, so the default leaves room for parallel builds.
	c.ExecMaxProcesses = uint64(envInt64("MCP_EXEC_MAX_PROCESSES", 512))
	c.ExecMaxOpenFiles = uint64(envInt64("MCP_EXEC_MAX_OPEN_FILES", 1024))
	c.ExecMaxFileBytes = uint64(envInt64("MCP_EXEC_MAX_FILE_BYTES", 1<<30))
	c.ExecDisableUserns = envBoolDefault("MCP_EXEC_DISABLE_USERNS", true)
	hardenSlirp := envBoolDefault("MCP_SLIRP_HARDENING", true)
	c.SlirpSandbox, c.SlirpSeccomp = hardenSlirp, hardenSlirp
	c.GitCredentialMode = envDefault("MCP_GIT_CREDENTIAL_MODE", "none")
	c.GitCredentialFile = strings.TrimSpace(os.Getenv("MCP_GIT_CREDENTIAL_FILE"))
	c.GitKnownHostsFile = strings.TrimSpace(os.Getenv("MCP_GIT_KNOWN_HOSTS_FILE"))
	for _, remote := range strings.Split(envDefault("MCP_GIT_ALLOWED_REMOTES", "origin"), ",") {
		if remote = strings.TrimSpace(remote); remote != "" {
			c.GitAllowedRemotes = append(c.GitAllowedRemotes, remote)
		}
	}
	// Remote MCP clients (Claude.ai connectors) call /mcp server-side with
	// their own Origin header; allow-list them instead of rejecting 403.
	c.AllowedOrigins = []string{"https://claude.ai", "https://claude.com"}
	if raw := strings.TrimSpace(os.Getenv("MCP_ALLOWED_ORIGINS")); raw != "" {
		c.AllowedOrigins = nil
		for _, part := range strings.Split(raw, ",") {
			if origin := strings.TrimSpace(part); origin != "" {
				c.AllowedOrigins = append(c.AllowedOrigins, strings.TrimRight(origin, "/"))
			}
		}
	}
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
	if err := c.validateAgentic(); err != nil {
		return Config{}, err
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
func envBool(k string) bool { v, _ := strconv.ParseBool(strings.TrimSpace(os.Getenv(k))); return v }

// envBoolDefault returns d when the variable is unset or not a valid boolean.
func envBoolDefault(k string, d bool) bool {
	raw := strings.TrimSpace(os.Getenv(k))
	if raw == "" {
		return d
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return d
	}
	return v
}

// helpMentions reports whether `binary --help` documents flag. It is used to
// enable optional hardening only on helper versions that support it.
func helpMentions(binary, flag string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, binary, "--help").CombinedOutput()
	return strings.Contains(string(out), flag)
}
func envInt(k string, d int) int {
	v, err := strconv.Atoi(envDefault(k, strconv.Itoa(d)))
	if err != nil {
		return -1
	}
	return v
}
func envInt64(k string, d int64) int64 {
	v, err := strconv.ParseInt(envDefault(k, strconv.FormatInt(d, 10)), 10, 64)
	if err != nil {
		return -1
	}
	return v
}
func envDuration(k string, d time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d
	}
	parsed, err := time.ParseDuration(v)
	if err != nil {
		return -1
	}
	return parsed
}
func isLoopback(host string) bool { ip := net.ParseIP(host); return ip != nil && ip.IsLoopback() }

func (c *Config) validateAgentic() error {
	if c.EnableGitNetwork && !c.EnableGitWrite {
		return errors.New("MCP_ENABLE_GIT_NETWORK requires MCP_ENABLE_GIT_WRITE")
	}
	if c.ExecTimeout <= 0 || c.ExecTimeout >= limits.HTTPTimeout || c.ExecJobTimeout < c.ExecTimeout || c.ExecJobTTL <= 0 {
		return errors.New("execution timeouts must be positive, MCP_EXEC_TIMEOUT must be shorter than HTTP timeout, and MCP_EXEC_JOB_TIMEOUT must not be shorter than MCP_EXEC_TIMEOUT")
	}
	if c.ExecMaxOutput < 4096 || c.ExecMaxOutput > 8<<20 || c.ExecMaxJobs < 1 || c.ExecMaxJobs > 64 || c.ExecMemoryBytes < 64<<20 || c.ExecCPUSeconds < 1 || c.ExecMaxProcesses < 8 || c.ExecMaxOpenFiles < 64 {
		return errors.New("execution resource limits are outside allowed ranges")
	}
	// Invalid numeric input parses to -1, which wraps to a huge unsigned value;
	// the upper bounds reject that as well as unreasonable settings.
	if c.ExecMemoryBytes > 1<<40 || c.ExecCPUSeconds > 1<<20 || c.ExecMaxProcesses > 1<<20 || c.ExecMaxOpenFiles > 1<<22 {
		return errors.New("execution resource limits are outside allowed ranges")
	}
	if c.ExecMaxFileBytes < 1<<20 || c.ExecMaxFileBytes > 1<<40 {
		return errors.New("MCP_EXEC_MAX_FILE_BYTES must be between 1 MiB and 1 TiB")
	}
	if !c.EnableExec && !c.EnableGitWrite {
		return nil
	}
	var err error
	if c.BwrapPath, err = exec.LookPath("bwrap"); err != nil {
		return errors.New("agentic features require bubblewrap (bwrap)")
	}
	if c.EnableExec || c.EnableGitNetwork {
		if c.Slirp4netnsPath, err = exec.LookPath("slirp4netns"); err != nil {
			return errors.New("networked agentic features require slirp4netns for isolated network egress")
		}
	}
	if c.SystemdRunPath, err = exec.LookPath("systemd-run"); err != nil {
		return errors.New("agentic features require systemd-run for cgroup resource limits")
	}
	if c.PrlimitPath, err = exec.LookPath("prlimit"); err != nil {
		return errors.New("agentic features require prlimit for process resource limits")
	}
	c.SystemctlPath, _ = exec.LookPath("systemctl")
	if c.ExecDisableUserns && !helpMentions(c.BwrapPath, "--disable-userns") {
		c.ExecDisableUserns = false
	}
	if c.Slirp4netnsPath != "" {
		c.SlirpSandbox = c.SlirpSandbox && helpMentions(c.Slirp4netnsPath, "--enable-sandbox")
		c.SlirpSeccomp = c.SlirpSeccomp && helpMentions(c.Slirp4netnsPath, "--enable-seccomp")
	} else {
		c.SlirpSandbox, c.SlirpSeccomp = false, false
	}
	if c.EnableGitNetwork {
		switch c.GitCredentialMode {
		case "none":
			if c.GitCredentialFile != "" || c.GitKnownHostsFile != "" {
				return errors.New("Git credential paths must be empty when MCP_GIT_CREDENTIAL_MODE=none")
			}
		case "ssh_key":
			if err := secureCredentialFile(c.GitCredentialFile, c.WorkspaceRoot); err != nil {
				return fmt.Errorf("invalid SSH credential file: %w", err)
			}
			if err := secureCredentialFile(c.GitKnownHostsFile, c.WorkspaceRoot); err != nil {
				return fmt.Errorf("invalid known-hosts file: %w", err)
			}
		case "https_token":
			if c.GitKnownHostsFile != "" {
				return errors.New("MCP_GIT_KNOWN_HOSTS_FILE is valid only for ssh_key mode")
			}
			if err := secureCredentialFile(c.GitCredentialFile, c.WorkspaceRoot); err != nil {
				return fmt.Errorf("invalid HTTPS credential file: %w", err)
			}
		default:
			return errors.New("MCP_GIT_CREDENTIAL_MODE must be none, ssh_key, or https_token")
		}
	}
	return nil
}

func secureCredentialFile(path, workspaceRoot string) error {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("path must be absolute")
	}
	path = filepath.Clean(path)
	if path == workspaceRoot || strings.HasPrefix(path, workspaceRoot+string(filepath.Separator)) {
		return errors.New("path must be outside workspace")
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 {
		return errors.New("file must be regular and mode 0600 or stricter")
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); !ok || sys.Nlink != 1 || int(sys.Uid) != os.Getuid() {
		return errors.New("file must be single-linked and owned by server user")
	}
	return nil
}
