package proxy

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"

	configsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	yaml "gopkg.in/yaml.v2"
)

// EffectiveEndpoints returns a privacy-safe list of endpoints + basic env info (site, dd_url).
func EffectiveEndpoints(extras []Endpoint) ([]Endpoint, EnvironmentInfo) {
	var (
		eps []Endpoint
		env EnvironmentInfo
	)

	cfg := configsetup.Datadog()

	// Resolve site
	site := "datadoghq.com"
	if cfg != nil {
		if s := strings.TrimSpace(cfg.GetString("site")); s != "" {
			site = s
		}
	} else if ddConf := os.Getenv("DD_CONF_DIR"); ddConf != "" {
		if s, _ := tryLoadSiteFromYAML(ddConf); s != "" {
			site = s
		}
	}

	// Resolve dd_url (control plane)
	ddURL := "https://app." + site
	if cfg != nil {
		if s := strings.TrimSpace(cfg.GetString("dd_url")); s != "" {
			ddURL = s
		}
	} else if ddConf := os.Getenv("DD_CONF_DIR"); ddConf != "" {
		if _, u := tryLoadSiteFromYAML(ddConf); strings.TrimSpace(u) != "" {
			ddURL = u
		}
	}

	env.Site = site
	env.DDURL = ddURL
	eps = append(eps, Endpoint{Name: "core", URL: ddURL})

	// Curated set of product intakes (hostnames matter for NO_PROXY).
	host := func(h string) string { return "https://" + h + "." + site }
	eps = append(eps,
		Endpoint{Name: "dbm-metrics", URL: host("dbm-metrics-intake")},
		Endpoint{Name: "ndm", URL: host("ndm-intake")},
		Endpoint{Name: "snmp-traps", URL: host("snmp-traps-intake")},
		Endpoint{Name: "netpath", URL: host("netpath-intake")},
		Endpoint{Name: "container-life", URL: host("contlcycle-intake")},
		Endpoint{Name: "container-image", URL: host("contimage-intake")},
		Endpoint{Name: "sbom", URL: host("sbom-intake")},
	)

	// Flare support
	eps = append(eps, Endpoint{Name: "flare", URL: "https://flare.agent." + site})

	// User-supplied extras (best-effort normalization)
	for _, ex := range extras {
		u := ex.URL
		if !strings.Contains(u, "://") {
			u = "https://" + u
		}
		eps = append(eps, Endpoint{Name: ex.Name, URL: u})
	}

	return eps, env
}

func splitNoProxyList(s string) []string {
	out := []string{}
	f := func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' }
	for _, tok := range strings.FieldsFunc(s, f) {
		tok = strings.TrimSpace(tok)
		if tok != "" {
			out = append(out, tok)
		}
	}
	return out
}

func getDefaultPortForScheme(scheme string) string {
	switch strings.ToLower(scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func domainMatches(host, suffix string) bool {
	// exact match or label-boundary suffix match
	h := strings.ToLower(host)
	s := strings.ToLower(suffix)
	if h == s {
		return true
	}
	return strings.HasSuffix(h, "."+s)
}

func normalizeToken(tok string) string {
	// trim brackets around IPv6 and spaces; lower for comparison
	tok = strings.TrimSpace(tok)
	tok = strings.Trim(tok, "[]")
	return strings.ToLower(tok)
}

func tokenMatches(host, port string, tok string, nonExact bool) bool {
	tok = normalizeToken(tok)
	hostL := strings.ToLower(host)

	// host:port tokens
	if h, p, ok := strings.Cut(tok, ":"); ok && p != "" {
		h = strings.Trim(h, "[]")
		if hostL == h || domainMatches(hostL, h) {
			return port == p
		}
		return false
	}
	// wildcard
	if tok == "*" {
		return true
	}
	// leading dot => domain+subdomains
	if strings.HasPrefix(tok, ".") {
		return domainMatches(hostL, strings.TrimPrefix(tok, "."))
	}
	// exact hostname
	if hostL == tok {
		return true
	}
	// optional substring mode (non-exact)
	if nonExact && strings.Contains(hostL, tok) {
		return true
	}
	return false
}

// EvaluateNoProxy computes which endpoints are bypassed by NO_PROXY.
func EvaluateNoProxy(eff Effective, eps []Endpoint) []EndpointCheck {
	matrix := make([]EndpointCheck, 0, len(eps))

	noProxy := strings.TrimSpace(eff.NoProxy.Value)
	rawTokens := splitNoProxyList(noProxy)
	// normalize & de-duplicate tokens
	tokens := make([]string, 0, len(rawTokens))
	seen := map[string]struct{}{}
	for _, t := range rawTokens {
		n := normalizeToken(t)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; !ok {
			seen[n] = struct{}{}
			tokens = append(tokens, n)
		}
	}

	for _, ep := range eps {
		u, err := url.Parse(ep.URL)
		if err != nil || u.Host == "" {
			continue
		}
		host := u.Hostname()
		port := u.Port()
		if port == "" {
			port = getDefaultPortForScheme(u.Scheme)
		}

		check := EndpointCheck{
			Endpoint: ep,
			Host:     host,
			Port:     port,
			Bypassed: false,
			Matched:  "",
		}

		for _, t := range tokens {
			if tokenMatches(host, port, t, eff.NonExactNoProxy) {
				check.Bypassed = true
				check.Matched = t
				break
			}
		}

		matrix = append(matrix, check)
	}

	return matrix
}

// minimal YAML shape for site/dd_url fallback from datadog.yaml
type ddSiteYAML struct {
	Site  string `yaml:"site"`
	DDURL string `yaml:"dd_url"`
}

func tryLoadSiteFromYAML(confDir string) (site, ddurl string) {
	if strings.TrimSpace(confDir) == "" {
		return "", ""
	}
	path := filepath.Join(confDir, "datadog.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	var doc ddSiteYAML
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return "", ""
	}
	return doc.Site, doc.DDURL
}
