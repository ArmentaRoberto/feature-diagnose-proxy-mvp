// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright ...

package flare

import (
	"github.com/DataDog/datadog-agent/comp/core/flare/types"
	dproxy "github.com/DataDog/datadog-agent/pkg/diagnose/proxy"
)

// collectProxyDiagnose writes a privacy-safe, config-only summary
// to diagnose/proxy.txt inside the flare. No network probes.
func (f *flare) collectProxyDiagnose(fb types.FlareBuilder) error {
	res := dproxy.Run(dproxy.Options{
		NoNetwork: true, // flares must not perform network activity
	})
	summary := dproxy.FormatSummary(res)
	return fb.AddFile("diagnose/proxy.txt", []byte(summary))
}
