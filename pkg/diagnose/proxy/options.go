package proxy

import "time"

// Options control how Run() executes.
type Options struct {
	NoNetwork      bool          // If true, do not run any active network probes.
	Timeout        time.Duration // Network dial timeout; if zero, defaults to 2s.
	Retries        int           // Retries per target; if negative, treated as zero.
	ExtraEndpoints []Endpoint    // Additional endpoints to evaluate against NO_PROXY.
}
