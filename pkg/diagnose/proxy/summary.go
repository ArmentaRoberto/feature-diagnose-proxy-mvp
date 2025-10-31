package proxy

import (
	"fmt"
	"strings"
	"time"
)

// FormatSummary renders a short privacy-safe block.
func FormatSummary(res Result) string {
	var b strings.Builder
	utc := time.Now().UTC().Format(time.RFC3339)
	fmt.Fprintf(&b, "=== Proxy/TLS Diagnose (privacy-safe, %s) ===\n", utc)
	fmt.Fprintf(&b, "Summary: %s\n", res.Summary)
	if res.Env.Site != "" || res.Env.DDURL != "" {
		fmt.Fprintf(&b, "Site: %s\n", res.Env.Site)
		fmt.Fprintf(&b, "DDURL: %s\n", res.Env.DDURL)
	}
	fmt.Fprintf(&b, "HTTPS: %q [%s]\n", RedactURL(res.Effective.HTTPS.Value), res.Effective.HTTPS.Source)
	fmt.Fprintf(&b, "HTTP : %q [%s]\n", RedactURL(res.Effective.HTTP.Value), res.Effective.HTTP.Source)
	if res.Effective.NoProxy.Value != "" {
		fmt.Fprintf(&b, "NO_PROXY: %q [%s]\n", res.Effective.NoProxy.Value, res.Effective.NoProxy.Source)
	}
	// Key findings (trim)
	count := 0
	for _, f := range res.Findings {
		if count >= 3 {
			b.WriteString("…\n")
			break
		}
		fmt.Fprintf(&b, "- [%s] %s\n", f.Severity, f.Description)
		count++
	}
	return b.String()
}
