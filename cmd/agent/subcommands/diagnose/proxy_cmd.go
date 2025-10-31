package diagnose

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	dproxy "github.com/DataDog/datadog-agent/pkg/diagnose/proxy"
	"github.com/spf13/cobra"
)

func newProxyCommand() *cobra.Command {
	var (
		format           string
		noNetwork        bool
		timeout          time.Duration
		retries          int
		includeSensitive bool     // reserved (hidden)
		extraEndpoints   []string // name=url OR url/host; repeat or comma-separate
		legacySummary    bool     // --summary (back-compat)
	)

	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Diagnose proxy/TLS configuration and common pitfalls",
		Long:  "Shows effective proxy settings with source precedence, lints common no_proxy/conflict issues, and can probe connectivity.",
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = includeSensitive // not used yet

			// Honor -c/--cfgpath by exporting DD_CONF_DIR for downstream config readers
			if f := cmd.InheritedFlags().Lookup("cfgpath"); f != nil {
				if v := f.Value.String(); v != "" {
					_ = os.Setenv("DD_CONF_DIR", v)
				}
			}

			parsedExtras := parseExtraEndpoints(extraEndpoints)

			// Back-compat: support --summary
			if legacySummary && strings.ToLower(format) == "text" {
				format = "summary"
			}

			// Back-compat: if parent --json is set, prefer JSON (unless --format explicitly set)
			if strings.ToLower(format) == "text" {
				isJSON := false
				// local (rare) then inherited (usual)
				if lf := cmd.Flags().Lookup("json"); lf != nil && lf.Changed {
					isJSON = true
				}
				if !isJSON {
					if pf := cmd.InheritedFlags().Lookup("json"); pf != nil {
						if b, err := strconv.ParseBool(pf.Value.String()); err == nil && b {
							isJSON = true
						}
					}
				}
				if isJSON {
					format = "json"
				}
			}

			switch strings.ToLower(format) {
			case "text", "json", "summary":
			default:
				return fmt.Errorf("invalid --format %q (valid: text,json,summary)", format)
			}

			opts := dproxy.Options{
				NoNetwork:      noNetwork,
				Timeout:        timeout,
				Retries:        retries,
				ExtraEndpoints: parsedExtras,
			}
			res := dproxy.Run(opts)

			switch strings.ToLower(format) {
			case "json":
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			case "summary":
				fmt.Print(dproxy.FormatSummary(res))
			default:
				printText(res)
			}

			// Exit non-zero on red summary for scripting ergonomics
			if res.Summary == dproxy.SeverityRed {
				return fmt.Errorf("proxy diagnose found blocking issues")
			}
			return nil
		},
	}

	// Flags
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text, json, or summary")
	cmd.Flags().BoolVar(&noNetwork, "no-network", true, "Do not run active network probes. Set to false to run TCP checks.")
	cmd.Flags().DurationVar(&timeout, "timeout", 2*time.Second, "Network probe timeout")
	cmd.Flags().IntVar(&retries, "retries", 0, "Network probe retries (per target)")
	cmd.Flags().StringSliceVar(&extraEndpoints, "endpoints", nil, "Extra endpoints to evaluate (repeat or comma-separate). Accepts name=url or host/url.")

	// Back-compat flag: --summary behaves like --format=summary
	cmd.Flags().BoolVar(&legacySummary, "summary", false, "Print a compact, privacy-safe summary block (alias of --format=summary)")

	// Hidden future flag
	cmd.Flags().BoolVar(&includeSensitive, "include-sensitive", false, "Include sensitive details (reserved)")
	_ = cmd.Flags().MarkHidden("include-sensitive")

	return cmd
}

func parseExtraEndpoints(tokens []string) []dproxy.Endpoint {
	out := []dproxy.Endpoint{}
	i := 0
	normalizeURL := func(s string) string {
		s = strings.TrimSpace(s)
		if s == "" {
			return s
		}
		if !strings.Contains(s, "://") {
			return "https://" + s
		}
		return s
	}
	for _, raw := range tokens {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			name := ""
			url := part
			if strings.Contains(part, "=") {
				k, v, _ := strings.Cut(part, "=")
				name, url = strings.TrimSpace(k), strings.TrimSpace(v)
			}
			if name == "" {
				i++
				name = fmt.Sprintf("extra-%d", i)
			}
			url = normalizeURL(url)
			out = append(out, dproxy.Endpoint{Name: name, URL: url})
		}
	}
	return out
}

func printText(res dproxy.Result) {
	fmt.Printf("Proxy/TLS Diagnose: %s\n", res.Summary)
	if res.Env.Site != "" || res.Env.DDURL != "" {
		fmt.Printf("  Site : %s\n", res.Env.Site)
		fmt.Printf("  DDURL: %s\n", res.Env.DDURL)
	}
	fmt.Println()

	fmt.Printf("Effective proxy (with sources):\n")
	fmt.Printf("  HTTPS    : %q [%s]\n", dproxy.RedactURL(res.Effective.HTTPS.Value), res.Effective.HTTPS.Source)
	fmt.Printf("  HTTP     : %q [%s]\n", dproxy.RedactURL(res.Effective.HTTP.Value), res.Effective.HTTP.Source)
	fmt.Printf("  NO_PROXY : %q [%s]\n\n", res.Effective.NoProxy.Value, res.Effective.NoProxy.Source)

	fmt.Println("NO_PROXY evaluation:")
	if len(res.EndpointMatrix) == 0 {
		fmt.Println("  (no endpoints discovered)")
	} else {
		for _, row := range res.EndpointMatrix {
			b := "no"
			if row.Bypassed {
				b = "YES"
			}
			fmt.Printf("  - %-14s host=%s port=%s bypassed=%s token=%q\n",
				row.Endpoint.Name, row.Host, row.Port, b, row.Matched)
		}
	}
	fmt.Println()

	if len(res.Findings) == 0 {
		fmt.Println("Findings: none. Looks good ✅")
		return
	}
	fmt.Println("Findings:")
	for _, f := range res.Findings {
		if f.DocURL != "" {
			fmt.Printf("  - [%s] %s\n    → %s\n    ℹ %s\n", f.Severity, f.Description, f.Action, f.DocURL)
		} else {
			fmt.Printf("  - [%s] %s\n    → %s\n", f.Severity, f.Description, f.Action)
		}
	}
}
