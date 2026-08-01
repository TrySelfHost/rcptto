package web

import (
	"bytes"
	"context"
	"encoding/csv"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xuri/excelize/v2"

	"github.com/tryselfhost/rcptto/internal/store"
	"github.com/tryselfhost/rcptto/pkg/verdict"
)

// uploadCSV posts a file to the preview endpoint.
func uploadFile(t *testing.T, h http.Handler, filename, content string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := part.Write([]byte(content)); err != nil {
		t.Fatalf("write part: %v", err)
	}
	_ = mw.Close()

	req, err := http.NewRequestWithContext(context.Background(), "POST", "/upload", &body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestUploadPreviewDetectsColumns(t *testing.T) {
	jb := &stubJobs{job: store.Job{ID: "job_1", Status: store.JobRunning, Total: 2}}
	h := New(Config{Verifier: stubVerifier{}, Jobs: jb}).Handler()

	rec := uploadFile(t, h, "clients.csv", "Client Name,Email\nAcme Ltd,a@acme.com\nBeta Inc,b@beta.com\n")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "clients.csv") {
		t.Errorf("preview should name the file: %s", body)
	}
	if !strings.Contains(body, "Acme Ltd") {
		t.Errorf("preview should show sample rows: %s", body)
	}
	if !strings.Contains(body, "/upload/confirm") {
		t.Errorf("preview should offer a confirm step: %s", body)
	}
	// The parsed sheet is staged, not verified — nothing submitted yet.
	if jb.submitted != nil {
		t.Errorf("preview must not submit a job; got %+v", jb.submitted)
	}
}

func TestUploadConfirmSubmitsLabelledRows(t *testing.T) {
	jb := &stubJobs{job: store.Job{ID: "job_1", Status: store.JobRunning, Total: 2}}
	srv := New(Config{Verifier: stubVerifier{}, Jobs: jb})
	h := srv.Handler()

	rec := uploadFile(t, h, "clients.csv", "Client Name,Email\nAcme Ltd,a@acme.com\nBeta Inc,b@beta.com\n")
	token := extractToken(t, rec.Body.String())

	form := "token=" + token + "&email_col=1&label_col=0"
	rec2 := do(t, h, "POST", "/upload/confirm", form)
	if rec2.Code != http.StatusOK {
		t.Fatalf("confirm status = %d, body = %s", rec2.Code, rec2.Body.String())
	}
	if len(jb.submitted) != 2 {
		t.Fatalf("submitted %d rows, want 2", len(jb.submitted))
	}
	if jb.submitted[0].Label != "Acme Ltd" || jb.submitted[0].Email != "a@acme.com" {
		t.Errorf("row[0] = %+v", jb.submitted[0])
	}
}

// An operator can override a wrong guess; the confirmed mapping must win.
func TestUploadConfirmHonoursOperatorColumnChoice(t *testing.T) {
	jb := &stubJobs{job: store.Job{ID: "job_1"}}
	h := New(Config{Verifier: stubVerifier{}, Jobs: jb}).Handler()

	rec := uploadFile(t, h, "c.csv", "Name,Email\nAcme,a@acme.com\n")
	token := extractToken(t, rec.Body.String())

	// Explicitly ask for no label column.
	rec2 := do(t, h, "POST", "/upload/confirm", "token="+token+"&email_col=1&label_col=-1")
	if rec2.Code != http.StatusOK {
		t.Fatalf("status = %d", rec2.Code)
	}
	if len(jb.submitted) != 1 || jb.submitted[0].Label != "" {
		t.Errorf("label should be empty when the operator selects none: %+v", jb.submitted)
	}
}

func TestUploadConfirmExpiredTokenRejected(t *testing.T) {
	h := New(Config{Verifier: stubVerifier{}, Jobs: &stubJobs{}}).Handler()
	rec := do(t, h, "POST", "/upload/confirm", "token=deadbeef&email_col=0&label_col=-1")
	if !strings.Contains(rec.Body.String(), "expired") {
		t.Errorf("expected an expiry message, got %s", rec.Body.String())
	}
}

func TestUploadRejectsUnsupportedType(t *testing.T) {
	h := New(Config{Verifier: stubVerifier{}, Jobs: &stubJobs{}}).Handler()
	rec := uploadFile(t, h, "list.pdf", "nonsense")
	if !strings.Contains(rec.Body.String(), "unsupported") {
		t.Errorf("expected an unsupported-type message, got %s", rec.Body.String())
	}
}

func TestExportCSVIncludesClientName(t *testing.T) {
	jb := &stubJobs{
		job: store.Job{ID: "job_1", Status: store.JobCompleted, Total: 1, Done: 1},
		results: []store.Result{{
			Label:   "Acme Ltd",
			Verdict: verdict.Verdict{Email: "a@acme.com", Status: verdict.StatusDeliverable, SubStatus: verdict.SubValidMailbox},
		}},
	}
	h := New(Config{Verifier: stubVerifier{}, Jobs: jb}).Handler()

	rec := do(t, h, "GET", "/jobs/job_1/export/csv", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("content-type = %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "job_1.csv") {
		t.Errorf("content-disposition = %q", cd)
	}

	records, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("export is not valid CSV: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("rows = %d, want header + 1 result", len(records))
	}
	if records[0][0] != "client" || records[0][1] != "email" {
		t.Errorf("header = %+v", records[0])
	}
	if records[1][0] != "Acme Ltd" || records[1][1] != "a@acme.com" || records[1][2] != "deliverable" {
		t.Errorf("row = %+v", records[1])
	}
}

func TestExportXLSXIsAValidWorkbook(t *testing.T) {
	jb := &stubJobs{
		job: store.Job{ID: "job_1", Status: store.JobCompleted, Total: 1, Done: 1},
		results: []store.Result{{
			Label:   "Beta Inc",
			Verdict: verdict.Verdict{Email: "b@beta.com", Status: verdict.StatusRisky},
		}},
	}
	h := New(Config{Verifier: stubVerifier{}, Jobs: jb}).Handler()

	rec := do(t, h, "GET", "/jobs/job_1/export/xlsx", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	f, err := excelize.OpenReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("export is not a readable workbook: %v", err)
	}
	defer func() { _ = f.Close() }()

	rows, err := f.GetRows(f.GetSheetList()[0])
	if err != nil {
		t.Fatalf("read rows: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want header + 1 result", len(rows))
	}
	if rows[1][0] != "Beta Inc" || rows[1][1] != "b@beta.com" {
		t.Errorf("row = %+v", rows[1])
	}
}

func TestExportUnknownJobIs404(t *testing.T) {
	jb := &stubJobs{getErr: store.ErrJobNotFound}
	h := New(Config{Verifier: stubVerifier{}, Jobs: jb}).Handler()
	if rec := do(t, h, "GET", "/jobs/missing/export/csv", ""); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestExportUnsupportedFormat(t *testing.T) {
	jb := &stubJobs{job: store.Job{ID: "job_1"}}
	h := New(Config{Verifier: stubVerifier{}, Jobs: jb}).Handler()
	if rec := do(t, h, "GET", "/jobs/job_1/export/pdf", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// extractToken pulls the staged-upload token out of the preview fragment.
func extractToken(t *testing.T, body string) string {
	t.Helper()
	const marker = `name="token" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("no token in preview: %s", body)
	}
	rest := body[i+len(marker):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		t.Fatal("malformed token field")
	}
	return rest[:j]
}
