package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func authedServer(t *testing.T) http.Handler {
	t.Helper()
	return New(Config{
		Verifier: stubVerifier{},
		Auth: &AuthConfig{
			Username: "admin",
			Password: "s3cret",
			Secret:   []byte("test-secret-key-for-signing-only"),
		},
	}).Handler()
}

// login performs a real login and returns the session cookie.
func login(t *testing.T, h http.Handler, user, pass string) *http.Cookie {
	t.Helper()
	body := url.Values{"username": {user}, "password": {pass}}.Encode()
	rec := do(t, h, "POST", "/login", body)
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	return nil
}

func TestUnauthenticatedRedirectsToLogin(t *testing.T) {
	h := authedServer(t)
	for _, path := range []string{"/", "/jobs", "/egress", "/policies"} {
		rec := do(t, h, "GET", path, "")
		if rec.Code != http.StatusSeeOther {
			t.Errorf("%s: status = %d, want 303 redirect", path, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/login" {
			t.Errorf("%s: redirected to %q, want /login", path, loc)
		}
	}
}

func TestLoginPageAndAssetsStayOpen(t *testing.T) {
	h := authedServer(t)
	if rec := do(t, h, "GET", "/login", ""); rec.Code != http.StatusOK {
		t.Errorf("/login status = %d, want 200", rec.Code)
	}
	if rec := do(t, h, "GET", "/assets/htmx.min.js", ""); rec.Code != http.StatusOK {
		t.Errorf("/assets status = %d, want 200", rec.Code)
	}
}

func TestLoginSuccessGrantsAccess(t *testing.T) {
	h := authedServer(t)
	cookie := login(t, h, "admin", "s3cret")
	if cookie == nil {
		t.Fatal("no session cookie issued on successful login")
	}
	if !cookie.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}

	req, err := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated request status = %d, want 200", rec.Code)
	}
}

func TestLoginFailureRejected(t *testing.T) {
	h := authedServer(t)
	for _, tc := range []struct{ user, pass string }{
		{"admin", "wrong"},
		{"wrong", "s3cret"},
		{"", ""},
	} {
		body := url.Values{"username": {tc.user}, "password": {tc.pass}}.Encode()
		rec := do(t, h, "POST", "/login", body)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%q/%q: status = %d, want 401", tc.user, tc.pass, rec.Code)
		}
		for _, c := range rec.Result().Cookies() {
			if c.Name == sessionCookieName && c.Value != "" {
				t.Errorf("%q/%q: session cookie issued on failed login", tc.user, tc.pass)
			}
		}
	}
}

func TestForgedCookieRejected(t *testing.T) {
	h := authedServer(t)
	future := time.Now().Add(time.Hour).Unix()
	for _, bad := range []string{
		"garbage",
		"9999999999.notasignature",
		strings.Join([]string{"9999999999", "AAAA"}, "."),
		// Correct shape, but signed with the wrong key.
		(&auth{secret: []byte("attacker-key")}).issueToken(time.Unix(future, 0)),
	} {
		req, err := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: bad})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusSeeOther {
			t.Errorf("forged cookie %q: status = %d, want redirect", bad, rec.Code)
		}
	}
}

func TestExpiredCookieRejected(t *testing.T) {
	a := &auth{secret: []byte("test-secret-key-for-signing-only")}
	expired := a.issueToken(time.Now().Add(-time.Minute))
	if a.validToken(expired) {
		t.Error("expired token must not validate")
	}
}

func TestHTMXRequestGetsRedirectHeader(t *testing.T) {
	h := authedServer(t)
	req, err := http.NewRequestWithContext(context.Background(), "POST", "/verify", strings.NewReader("email=a@b.com"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for htmx request", rec.Code)
	}
	if got := rec.Header().Get("HX-Redirect"); got != "/login" {
		t.Errorf("HX-Redirect = %q, want /login", got)
	}
}

func TestLogoutClearsSession(t *testing.T) {
	h := authedServer(t)
	cookie := login(t, h, "admin", "s3cret")

	req, err := http.NewRequestWithContext(context.Background(), "POST", "/logout", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("logout must clear the session cookie")
	}
}

func TestNoAuthConfiguredLeavesDashboardOpen(t *testing.T) {
	h := New(Config{Verifier: stubVerifier{}}).Handler()
	if rec := do(t, h, "GET", "/", ""); rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 when auth is disabled", rec.Code)
	}
}

func TestIncompleteAuthConfigPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected panic when password is missing")
		}
	}()
	New(Config{Verifier: stubVerifier{}, Auth: &AuthConfig{Username: "admin"}})
}
