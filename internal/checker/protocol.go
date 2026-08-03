// Package checker provides checker identity pinning and protocol constants.
package checker

// Protocol exit codes for checker processes.
const (
	// ExitPass indicates the claim was verified successfully.
	ExitPass = 0
	// ExitFail indicates the claim was disproved or verification failed.
	ExitFail = 1
	// ExitUnavailable indicates the checker cannot run (missing dependency, etc.).
	ExitUnavailable = 2
	// ExitProtocolError indicates the checker violated the protocol (bad output, etc.).
	ExitProtocolError = 3
)

// ProtocolVersion is the current checker protocol version.
const ProtocolVersion = 1

// Resource limits for checker invocations.
const (
	// DefaultWallTimeoutSec is the default wall-clock timeout for a checker.
	DefaultWallTimeoutSec = 300
	// MaxMemBytes is the maximum memory a checker may consume.
	MaxMemBytes = 4 * 1024 * 1024 * 1024 // 4 GiB
)
