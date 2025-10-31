package proxy

type Source string

const (
	SourceDefault Source = "default"
	SourceStdEnv  Source = "std_env"
	SourceConfig  Source = "config"
	SourceDDEnv   Source = "dd_env"
)

type ValueWithSource struct {
	Value  string `json:"value"`
	Source Source `json:"source"`
}

type Effective struct {
	HTTP            ValueWithSource `json:"http"`
	HTTPS           ValueWithSource `json:"https"`
	NoProxy         ValueWithSource `json:"no_proxy"`
	NonExactNoProxy bool            `json:"non_exact_no_proxy"`
}

type Severity string

const (
	SeverityGreen  Severity = "green"
	SeverityYellow Severity = "yellow"
	SeverityRed    Severity = "red"
)

type Finding struct {
	Code        string   `json:"code"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	Action      string   `json:"action"`
	Evidence    any      `json:"evidence,omitempty"`
	DocURL      string   `json:"doc_url,omitempty"`
}

type Endpoint struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type EndpointCheck struct {
	Endpoint Endpoint `json:"endpoint"`
	Host     string   `json:"host"`
	Port     string   `json:"port"`
	Bypassed bool     `json:"bypassed"`
	Matched  string   `json:"matched_token,omitempty"`
}

type Conflict struct {
	Key    string            `json:"key"`
	Values []ValueWithSource `json:"values"`
}

// EnvironmentInfo summarizes key inputs that influence endpoint resolution.
type EnvironmentInfo struct {
	Site  string `json:"site"`
	DDURL string `json:"dd_url"`
}

// SchemaVersion is returned with Result so downstream tools can evolve safely.
const SchemaVersion = "v1"

type Result struct {
	SchemaVersion string          `json:"schema_version"`
	Env           EnvironmentInfo `json:"env"`
	Summary       Severity        `json:"summary"`
	Effective     Effective       `json:"effective"`
	Findings      []Finding       `json:"findings"`
	EndpointMatrix []EndpointCheck `json:"endpoint_matrix"` // always present (possibly [])
	Conflicts     []Conflict      `json:"conflicts,omitempty"`
}
