package proxy

// Run executes config lints and, if enabled, minimal network probes.
// - Config lints always run.
// - When opts.NoNetwork == false, we also attempt TCP dials to proxies.
func Run(opts Options) Result {
	eff := ComputeEffective()
	findings := []Finding{}

	// Config lints
	findings = append(findings, LintAll(eff)...)
	findings = append(findings, lintURLShapes(eff)...)
	findings = append(findings, lintConflicts(eff)...)

	// Config-only endpoint evaluation (privacy-safe)
	eps, env := EffectiveEndpoints(opts.ExtraEndpoints)
	matrix := EvaluateNoProxy(eff, eps)
	if matrix == nil {
		// ensure endpoint_matrix is always [] in JSON, never null
		matrix = []EndpointCheck{}
	}

	for _, row := range matrix {
		if row.Bypassed {
			findings = append(findings, Finding{
				Code:        "no_proxy.endpoint_bypassed",
				Severity:    SeverityYellow,
				Description: row.Endpoint.Name + " endpoint will bypass the proxy due to NO_PROXY",
				Action:      "Remove or narrow the NO_PROXY token if unintended.",
				Evidence: map[string]string{
					"endpoint": row.Endpoint.Name,
					"host":     row.Host,
					"token":    row.Matched,
				},
				DocURL: "https://docs.datadoghq.com/agent/configuration/proxy/",
			})
		}
	}

	// Minimal active probes (off by default)
	if !opts.NoNetwork {
		findings = append(findings, ProbeProxyConnectivity(eff, opts.Timeout, opts.Retries)...)
		findings = append(findings, ProbeEndpointsConnectivity(eff, eps)...)
	}

	// Summary rollup
	summary := SeverityGreen
	for _, f := range findings {
		if f.Severity == SeverityRed {
			summary = SeverityRed
			break
		}
		if f.Severity == SeverityYellow && summary == SeverityGreen {
			summary = SeverityYellow
		}
	}

	confs := CollectConflicts(eff)

	return Result{
		SchemaVersion:  SchemaVersion,
		Env:            env,
		Summary:        summary,
		Effective:      eff,
		Findings:       findings,
		EndpointMatrix: matrix,
		Conflicts:      confs,
	}
}
