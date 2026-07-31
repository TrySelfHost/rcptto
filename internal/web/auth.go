package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// sessionCookieName is the cookie holding the signed dashboard session.
const sessionCookieName = "rcptto_session"

// defaultSessionTTL is how long a dashboard login stays valid.
const defaultSessionTTL = 12 * time.Hour

// AuthConfig enables password protection for the dashboard. The dashboard can
// quarantine egress identities and rewrite provider policy, so it must never be
// exposed to an untrusted network without this (or an authenticating proxy in
// front of it).
type AuthConfig struct {
	// Username and Password are the dashboard credentials. Both required.
	Username string
	Password string
	// Secret signs session cookies. If empty, a random secret is generated at
	// startup, which is secure but invalidates existing sessions on restart.
	Secret []byte
	// TTL is the session lifetime; defaults to 12h.
	TTL time.Duration
	// SecureCookie sets the Secure flag, which requires HTTPS. Enable this
	// whenever the dashboard is served over TLS (i.e. any real deployment).
	SecureCookie bool
}

// auth holds the resolved authentication state.
type auth struct {
	username     string
	password     string
	secret       []byte
	ttl          time.Duration
	secureCookie bool
}

// newAuth validates and normalizes an AuthConfig. It returns an error rather
// than silently disabling protection, so a misconfiguration fails loudly
// instead of quietly serving an unprotected dashboard.
func newAuth(cfg *AuthConfig) (*auth, error) {
	if cfg == nil {
		return nil, nil
	}
	if cfg.Username == "" || cfg.Password == "" {
		return nil, fmt.Errorf("web: dashboard auth requires both a username and a password")
	}
	a := &auth{
		username:     cfg.Username,
		password:     cfg.Password,
		secret:       cfg.Secret,
		ttl:          cfg.TTL,
		secureCookie: cfg.SecureCookie,
	}
	if a.ttl <= 0 {
		a.ttl = defaultSessionTTL
	}
	if len(a.secret) == 0 {
		a.secret = make([]byte, 32)
		if _, err := rand.Read(a.secret); err != nil {
			return nil, fmt.Errorf("web: generating session secret: %w", err)
		}
	}
	return a, nil
}

// checkCredentials compares submitted credentials in constant time, so response
// timing does not leak how much of the username or password matched.
func (a *auth) checkCredentials(username, password string) bool {
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(a.username)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(password), []byte(a.password)) == 1
	return userOK && passOK
}

// issueToken builds a signed session token valid until the given expiry. The
// token is "<expiryUnix>.<base64 hmac>"; there is no server-side session store,
// which keeps the binary stateless.
func (a *auth) issueToken(expiry time.Time) string {
	exp := strconv.FormatInt(expiry.Unix(), 10)
	return exp + "." + base64.RawURLEncoding.EncodeToString(a.sign(exp))
}

// validToken reports whether a token is correctly signed and unexpired.
func (a *auth) validToken(token string) bool {
	exp, sig, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}
	want := a.sign(exp)
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	if !hmac.Equal(want, got) {
		return false
	}
	unix, err := strconv.ParseInt(exp, 10, 64)
	if err != nil {
		return false
	}
	return time.Now().Before(time.Unix(unix, 0))
}

func (a *auth) sign(payload string) []byte {
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte(payload))
	return mac.Sum(nil)
}

// authenticated reports whether a request carries a valid session cookie.
func (s *Server) authenticated(r *http.Request) bool {
	if s.auth == nil {
		return true // auth disabled
	}
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	return s.auth.validToken(c.Value)
}

// requireAuth wraps the dashboard mux, redirecting unauthenticated browsers to
// the login page. The login route and static assets stay open so the login page
// can render.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	if s.auth == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/login") || strings.HasPrefix(r.URL.Path, "/assets/") {
			next.ServeHTTP(w, r)
			return
		}
		if s.authenticated(r) {
			next.ServeHTTP(w, r)
			return
		}
		// htmx swaps must not receive a login page as a fragment; tell the
		// client to do a full-page redirect instead.
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Redirect", "/login")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
}

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil || s.authenticated(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.renderPage(w, "rcpttō — Sign in", "content-login", struct{ Error string }{})
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderPage(w, "rcpttō — Sign in", "content-login", struct{ Error string }{"Invalid form submission."})
		return
	}
	if !s.auth.checkCredentials(r.FormValue("username"), r.FormValue("password")) {
		w.WriteHeader(http.StatusUnauthorized)
		s.renderPage(w, "rcpttō — Sign in", "content-login", struct{ Error string }{"Incorrect username or password."})
		return
	}

	expiry := time.Now().Add(s.auth.ttl)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    s.auth.issueToken(expiry),
		Path:     "/",
		Expires:  expiry,
		HttpOnly: true,
		Secure:   s.auth.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.auth != nil && s.auth.secureCookie,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
