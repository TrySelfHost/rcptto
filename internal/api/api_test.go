package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// stubVerifier returns a canned verdict (or error) for any address.
type stubVerifier struct {
	v   verdict.Verdict
	err error
}

func (s stubVerifier) Verify(context.Context, string) (verdict.Verdict, error) {
	return s.v, s.err
}

func doJSON(t *testing.T, h http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestVerifyOK(t *testing.T) {
	want := verdict.Verdict{Email: "a@b.com", Status: verdict.StatusDeliverable, SubStatus: verdict.SubValidMailbox}
	h := New(Config{Verifier: stubVerifier{v: want}}).Handler()

	rec := doJSON(t, h, "POST", "/v1/verify", `{"email":"a@b.com"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got verdict.Verdict
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Status != verdict.StatusDeliverable {
		t.Errorf("status = %s", got.Status)
	}
}

func TestVerifyMissingEmail(t *testing.T) {
	h := New(Config{Verifier: stubVerifier{}}).Handler()
	rec := doJSON(t, h, "POST", "/v1/verify", `{"email":"   "}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("content-type = %q", ct)
	}
}

func TestVerifyInvalidJSON(t *testing.T) {
	h := New(Config{Verifier: stubVerifier{}}).Handler()
	rec := doJSON(t, h, "POST", "/v1/verify", `{not json`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestVerifyUnknownField(t *testing.T) {
	h := New(Config{Verifier: stubVerifier{}}).Handler()
	rec := doJSON(t, h, "POST", "/v1/verify", `{"email":"a@b.com","x":1}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field should be rejected, status = %d", rec.Code)
	}
}

func TestAuthRequired(t *testing.T) {
	h := New(Config{Verifier: stubVerifier{}, APIKeys: []string{"secret"}}).Handler()

	// Missing key -> 401.
	rec := doJSON(t, h, "POST", "/v1/verify", `{"email":"a@b.com"}`, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing key: status = %d", rec.Code)
	}

	// Correct key -> 200.
	rec = doJSON(t, h, "POST", "/v1/verify", `{"email":"a@b.com"}`, map[string]string{"X-API-Key": "secret"})
	if rec.Code != http.StatusOK {
		t.Fatalf("valid key: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHealthAndReadyOpenWithoutKey(t *testing.T) {
	h := New(Config{Verifier: stubVerifier{}, APIKeys: []string{"secret"}}).Handler()
	for _, path := range []string{"/healthz", "/readyz"} {
		rec := doJSON(t, h, "GET", path, "", nil)
		if rec.Code != http.StatusOK {
			t.Errorf("%s status = %d (should be open without auth)", path, rec.Code)
		}
	}
}

func TestMethodMismatch(t *testing.T) {
	h := New(Config{Verifier: stubVerifier{}}).Handler()
	rec := doJSON(t, h, "GET", "/v1/verify", "", nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}
