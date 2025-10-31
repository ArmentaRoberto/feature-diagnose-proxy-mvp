package proxy

import (
	"context"
	"net"
	"net/url"
	"strings"
	"time"
)

// ProbeProxyConnectivity performs a minimal active probe when network checks are enabled.
// It attempts a TCP connection to the configured HTTPS and/or HTTP proxy.
// If this fails, we report a red finding. This avoids CONNECT/TLS/HTTP in the MVP.
func ProbeProxyConnectivity(eff Effective, timeout time.Duration, retries int) []Finding {
	var out []Finding

	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if retries < 0 {
		retries = 0
	}

	type target struct {
		key    string // "https" or "http"
		rawURL string
	}
	var targets []target
	if eff.HTTPS.Value != "" {
		targets = append(targets, target{key: "https", rawURL: eff.HTTPS.Value})
	}
	if eff.HTTP.Value != "" {
		targets = append(targets, target{key: "http", rawURL: eff.HTTP.Value})
	}
	if len(targets) == 0 {
		return out
	}

	for _, t := range targets {
		u, err := url.Parse(t.rawURL)
		if err != nil || u.Host == "" {
			// Shape/parse problems are covered by lints; skip probe for this one.
			continue
		}

		// Determine host:port; default ports if missing.
		addr := u.Host
		if _, _, err := net.SplitHostPort(addr); err != nil {
			switch u.Scheme {
			case "http":
				addr = net.JoinHostPort(u.Host, "80")
			case "https":
				addr = net.JoinHostPort(u.Host, "443")
			default:
				// Non-standard/unknown schemes are flagged by lints; skip active probe.
				continue
			}
		}

		// Fast TCP dial to the proxy, with optional retries.
		var lastErr error
		attempts := retries + 1
		for i := 0; i < attempts; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			d := net.Dialer{}
			conn, err := d.DialContext(ctx, "tcp", addr)
			cancel()
			if err == nil {
				_ = conn.Close()
				lastErr = nil
				break
			}
			lastErr = err
		}

		if lastErr != nil {
			out = append(out, Finding{
				Code:        "proxy." + t.key + ".connect_failed",
				Severity:    SeverityRed,
				Description: "Failed to connect to the configured " + strings.ToUpper(t.key) + " proxy.",
				Action:      "Verify host/port, firewall, routing, and that the proxy is reachable.",
				Evidence: map[string]string{
					"target": addr,
					"error":  lastErr.Error(),
				},
			})
		}
	}

	return out
}

// Future enhancement: DNS/TCP/TLS/HTTP probes per intake when --no-network=false.
func ProbeEndpointsConnectivity(_ Effective, _ []Endpoint) []Finding {
	return nil
}
