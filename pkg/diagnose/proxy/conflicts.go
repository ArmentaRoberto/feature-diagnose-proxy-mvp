package proxy

import (
	"os"
	"strings"

	configsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
)

// lintConflicts emits findings for conflicting proxy values across sources.
func lintConflicts(eff Effective) []Finding {
	var out []Finding
	confs := CollectConflicts(eff)
	for _, c := range confs {
		key := c.Key
		out = append(out, Finding{
			Code:        "proxy." + key + ".conflict",
			Severity:    SeverityYellow,
			Description: strings.ToUpper(key) + " proxy is defined by multiple sources with different values.",
			Action:      "Use a single source or align the values across sources.",
			Evidence:    c.Values,
			DocURL:      "https://docs.datadoghq.com/agent/configuration/proxy/",
		})
	}
	return out
}

// CollectConflicts returns structured conflicts for consumers and inclusion in Result.
func CollectConflicts(eff Effective) []Conflict {
	cfg := configsetup.Datadog()

	collect := func(key string) []ValueWithSource {
		values := []ValueWithSource{}

		// dd env
		if key == "https" {
			if v := strings.TrimSpace(os.Getenv("DD_PROXY_HTTPS")); v != "" {
				values = append(values, ValueWithSource{Value: v, Source: SourceDDEnv})
			}
		} else {
			if v := strings.TrimSpace(os.Getenv("DD_PROXY_HTTP")); v != "" {
				values = append(values, ValueWithSource{Value: v, Source: SourceDDEnv})
			}
		}

		// config
		if cfg != nil {
			if key == "https" {
				if v := strings.TrimSpace(cfg.GetString("proxy.https")); v != "" {
					values = append(values, ValueWithSource{Value: v, Source: SourceConfig})
				}
			} else {
				if v := strings.TrimSpace(cfg.GetString("proxy.http")); v != "" {
					values = append(values, ValueWithSource{Value: v, Source: SourceConfig})
				}
			}
		}

		// std env
		if key == "https" {
			if v := strings.TrimSpace(os.Getenv("HTTPS_PROXY")); v != "" {
				values = append(values, ValueWithSource{Value: v, Source: SourceStdEnv})
			}
		} else {
			if v := strings.TrimSpace(os.Getenv("HTTP_PROXY")); v != "" {
				values = append(values, ValueWithSource{Value: v, Source: SourceStdEnv})
			}
		}

		// Lowercase variants (last resort)
		if key == "https" && len(values) == 0 {
			if v := strings.TrimSpace(os.Getenv("https_proxy")); v != "" {
				values = append(values, ValueWithSource{Value: v, Source: SourceStdEnv})
			}
		}
		if key == "http" && len(values) == 0 {
			if v := strings.TrimSpace(os.Getenv("http_proxy")); v != "" {
				values = append(values, ValueWithSource{Value: v, Source: SourceStdEnv})
			}
		}

		// de-dup by value
		uniq := make(map[string]Source)
		out := []ValueWithSource{}
		for _, vv := range values {
			if _, seen := uniq[vv.Value]; !seen {
				uniq[vv.Value] = vv.Source
				out = append(out, vv)
			}
		}
		return out
	}

	out := []Conflict{}
	if vals := collect("https"); len(vals) > 1 {
		out = append(out, Conflict{Key: "https", Values: vals})
	}
	if vals := collect("http"); len(vals) > 1 {
		out = append(out, Conflict{Key: "http", Values: vals})
	}
	return out
}
