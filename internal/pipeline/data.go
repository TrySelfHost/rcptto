package pipeline

import "strings"

// Provider class identifiers. These are stable strings recorded in verdicts and
// consumed by the (future) provider-policy engine.
const (
	providerGmail           = "gmail"
	providerMicrosoft       = "microsoft"
	providerYahoo           = "yahoo"
	providerApple           = "icloud"
	providerProton          = "proton"
	providerGoogleWorkspace = "google_workspace"
	providerMicrosoft365    = "microsoft365"
	providerCustom          = "custom"
)

// providerDomains maps well-known consumer mail domains to a provider class.
var providerDomains = map[string]string{
	"gmail.com":      providerGmail,
	"googlemail.com": providerGmail,

	"outlook.com":   providerMicrosoft,
	"hotmail.com":   providerMicrosoft,
	"hotmail.co.uk": providerMicrosoft,
	"live.com":      providerMicrosoft,
	"msn.com":       providerMicrosoft,

	"yahoo.com":      providerYahoo,
	"yahoo.co.uk":    providerYahoo,
	"ymail.com":      providerYahoo,
	"rocketmail.com": providerYahoo,

	"icloud.com": providerApple,
	"me.com":     providerApple,
	"mac.com":    providerApple,

	"proton.me":      providerProton,
	"protonmail.com": providerProton,
	"pm.me":          providerProton,
}

// freeDomains is the set of well-known free consumer providers. Free status is
// informational: it downgrades confidence but is not, by itself, terminal.
var freeDomains = toSet([]string{
	"gmail.com", "googlemail.com",
	"outlook.com", "hotmail.com", "hotmail.co.uk", "live.com", "msn.com",
	"yahoo.com", "yahoo.co.uk", "ymail.com", "rocketmail.com",
	"aol.com", "icloud.com", "me.com", "mac.com",
	"proton.me", "protonmail.com", "pm.me",
	"gmx.com", "gmx.net", "zoho.com", "yandex.com", "mail.com", "tutanota.com",
})

// roleLocalParts is the set of local-parts that denote a shared role account
// rather than an individual mailbox. Compared case-insensitively.
var roleLocalParts = toSet([]string{
	"admin", "administrator", "info", "support", "sales", "contact", "help",
	"billing", "marketing", "office", "hello", "team", "mail", "noreply",
	"no-reply", "donotreply", "do-not-reply", "postmaster", "hostmaster",
	"webmaster", "abuse", "security", "root", "sysadmin", "careers", "jobs",
	"hr", "press", "media", "newsletter", "notifications", "service",
	"enquiries", "inquiries", "feedback", "orders", "accounts", "accounting",
	"finance", "legal", "compliance",
})

// defaultDisposable is a small embedded starter set of throwaway providers. A
// larger vendored list (e.g. the mailchecker database) can be substituted via
// Config.Disposable without changing the stage.
var defaultDisposable = toSet([]string{
	"mailinator.com", "guerrillamail.com", "10minutemail.com", "temp-mail.org",
	"yopmail.com", "throwawaymail.com", "getnada.com", "trashmail.com",
	"maildrop.cc", "dispostable.com", "fakeinbox.com", "sharklasers.com",
	"guerrillamailblock.com", "mailnesia.com", "mohmal.com", "tempmail.dev",
})

// mapSet is the default DisposableSet backed by an in-memory map.
type mapSet map[string]struct{}

func (m mapSet) Contains(domain string) bool {
	_, ok := m[domain]
	return ok
}

func defaultDisposableSet() DisposableSet { return mapSet(defaultDisposable) }

// providerForDomain returns the provider class for a domain, or "" if unknown.
func providerForDomain(domain string) string {
	return providerDomains[domain]
}

// isRoleAccount reports whether local is a shared role account. The comparison
// is case-insensitive.
func isRoleAccount(local string) bool {
	_, ok := roleLocalParts[strings.ToLower(local)]
	return ok
}

// isFreeDomain reports whether domain is a known free consumer provider.
func isFreeDomain(domain string) bool {
	_, ok := freeDomains[domain]
	return ok
}

// refineProviderFromMX infers a provider class from resolved MX hostnames,
// enabling detection of Google Workspace and Microsoft 365 on custom domains.
// It returns "" when the MX set gives no strong signal.
func refineProviderFromMX(mx []string) string {
	for _, host := range mx {
		h := strings.ToLower(strings.TrimSuffix(host, "."))
		switch {
		case strings.HasSuffix(h, "google.com") || strings.HasSuffix(h, "googlemail.com"):
			return providerGoogleWorkspace
		case strings.HasSuffix(h, "outlook.com") || strings.HasSuffix(h, "protection.outlook.com"):
			return providerMicrosoft365
		}
	}
	return ""
}

// toSet builds a lookup set from a slice of keys.
func toSet(keys []string) map[string]struct{} {
	m := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		m[k] = struct{}{}
	}
	return m
}
