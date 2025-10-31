package proxy

import (
	"net/url"
	"strings"
)

// RedactURL removes user:pass@ and obvious secrets in query params for display purposes.
// If parsing fails, returns the input unchanged.
func RedactURL(raw string) string {
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.User != nil {
		u.User = url.User("****")
	}
	// Redact common credential-like query params
	q := u.Query()
	for k := range q {
		kl := strings.ToLower(k)
		if strings.Contains(kl, "key") ||
			strings.Contains(kl, "token") ||
			strings.Contains(kl, "secret") ||
			strings.Contains(kl, "password") ||
			strings.Contains(kl, "passwd") {
			q.Set(k, "****")
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}
