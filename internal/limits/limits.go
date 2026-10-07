// Package limits centralizes all externally observable resource limits.
package limits

import "time"

const (
	MaxRequestBody            int64 = 1 << 20
	MaxFileBytes                    = 1 << 20
	MaxWriteBytes                   = 1 << 20
	DefaultListDepth                = 2
	MaxListDepth                    = 8
	MaxListEntries                  = 2_000
	MaxListResultBytes              = 512 << 10
	DefaultSearchResults            = 50
	MaxSearchResults                = 200
	MaxSearchFiles                  = 10_000
	MaxSearchBytes                  = 64 << 20
	MaxSearchLineBytes              = 64 << 10
	MaxSearchContextLines           = 20
	MaxSearchIncludeGlobs           = 32
	MaxSearchResultBytes            = 512 << 10
	MaxPathBytes                    = 4_096
	MaxPathComponent                = 255
	MaxParentDepth                  = 64
	MaxGitOutput                    = 1 << 20
	MaxGitPaths                     = 256
	MaxGitCommitMessageBytes        = 64 << 10
	MaxExecOutput                   = 512 << 10
	MaxExecArgs                     = 256
	MaxExecArgBytes                 = 64 << 10
	MaxExecEnv                      = 64
	MaxExecScriptBytes              = 256 << 10
	MaxExecJobs                     = 8
	MaxExecConcurrency              = 2
	MaxRecursiveDeleteEntries       = 10_000
	MaxGlobResults                  = 2_000
	MaxGlobScanEntries              = 10_000
	MaxPatchFiles                   = 128
	MaxHTTPConcurrency              = 32
)

const (
	ToolTimeout        = 15 * time.Second
	GitTimeout         = 10 * time.Second
	ExecTimeout        = 15 * time.Second
	ExecJobTimeout     = 10 * time.Minute
	ExecJobTTL         = 30 * time.Minute
	HTTPTimeout        = 30 * time.Second
	HTTPHeaderTimeout  = 10 * time.Second
	ShutdownTimeout    = 10 * time.Second
	AccessTokenTTL     = 15 * time.Minute
	RefreshTokenTTL    = 30 * 24 * time.Hour
	AuthorizationTTL   = 5 * time.Minute
	SessionIdleTTL     = 30 * time.Minute
	SessionAbsoluteTTL = 8 * time.Hour
)
