package web

import (
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/xuri/excelize/v2"

	"github.com/tryselfhost/rcptto/internal/ingest"
	"github.com/tryselfhost/rcptto/internal/jobs"
	"github.com/tryselfhost/rcptto/internal/store"
)

// Upload limits.
const (
	maxUploadBytes   = 32 << 20 // 32 MiB
	pendingTTL       = 15 * time.Minute
	maxPendingUpload = 8
	exportPageSize   = 500
)

// pendingUpload is a parsed sheet awaiting the operator's confirmation of which
// columns to use. Parsing and submission are deliberately separate steps: a
// mis-detected email column would send a whole list of garbage at real mail
// servers, so the mapping is shown for review first.
type pendingUpload struct {
	filename string
	sheet    *ingest.Sheet
	created  time.Time
}

// uploadCache holds parsed sheets between the preview and confirm requests.
// It is intentionally in-memory and short-lived: an upload that is never
// confirmed is not worth persisting.
type uploadCache struct {
	mu    sync.Mutex
	items map[string]pendingUpload
}

func newUploadCache() *uploadCache {
	return &uploadCache{items: make(map[string]pendingUpload)}
}

func (c *uploadCache) put(u pendingUpload) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b[:])

	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictLocked()
	// Bound memory: drop the oldest if the operator has stacked up uploads.
	for len(c.items) >= maxPendingUpload {
		var oldestKey string
		var oldest time.Time
		for k, v := range c.items {
			if oldest.IsZero() || v.created.Before(oldest) {
				oldestKey, oldest = k, v.created
			}
		}
		delete(c.items, oldestKey)
	}
	c.items[token] = u
	return token, nil
}

func (c *uploadCache) get(token string) (pendingUpload, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictLocked()
	u, ok := c.items[token]
	return u, ok
}

func (c *uploadCache) drop(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, token)
}

// evictLocked removes expired uploads. Caller must hold the lock.
func (c *uploadCache) evictLocked() {
	cutoff := time.Now().Add(-pendingTTL)
	for k, v := range c.items {
		if v.created.Before(cutoff) {
			delete(c.items, k)
		}
	}
}

// uploadPreview is the view model for the column-mapping step.
type uploadPreview struct {
	Token    string
	Filename string
	Header   []string
	Rows     [][]string
	Columns  []int
	EmailCol int
	LabelCol int
	Total    int
	// Error is shown above the mapping controls when a confirmation failed for
	// a reason the operator can correct without re-uploading.
	Error string
}

// handleUploadPreview parses an uploaded sheet and shows the detected column
// mapping for confirmation.
func (s *Server) handleUploadPreview(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Jobs == nil {
		http.Error(w, "bulk jobs are not enabled on this server", http.StatusNotImplemented)
		return
	}
	if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
		s.renderFragment(w, "verdict-error", "could not read the upload: "+err.Error())
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		s.renderFragment(w, "verdict-error", "choose a .csv or .xlsx file to upload")
		return
	}
	defer func() { _ = file.Close() }()

	sheet, err := ingest.Parse(header.Filename, file)
	if err != nil {
		s.renderFragment(w, "verdict-error", err.Error())
		return
	}

	token, err := s.uploads.put(pendingUpload{filename: header.Filename, sheet: sheet, created: time.Now()})
	if err != nil {
		s.renderFragment(w, "verdict-error", "could not stage the upload")
		return
	}

	emailCol, labelCol := sheet.DetectColumns()
	s.renderFragment(w, "upload-preview", buildPreview(token, header.Filename, sheet, emailCol, labelCol))
}

func buildPreview(token, filename string, sheet *ingest.Sheet, emailCol, labelCol int) uploadPreview {
	width := 0
	for _, row := range sheet.Preview() {
		if len(row) > width {
			width = len(row)
		}
	}
	if len(sheet.Header) > width {
		width = len(sheet.Header)
	}
	cols := make([]int, width)
	for i := range cols {
		cols[i] = i
	}
	return uploadPreview{
		Token: token, Filename: filename,
		Header: sheet.Header, Rows: sheet.Preview(), Columns: cols,
		EmailCol: emailCol, LabelCol: labelCol, Total: len(sheet.Rows),
	}
}

// handleUploadConfirm turns a confirmed column mapping into a verification job.
func (s *Server) handleUploadConfirm(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Jobs == nil {
		http.Error(w, "bulk jobs are not enabled on this server", http.StatusNotImplemented)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderFragment(w, "verdict-error", "invalid form submission")
		return
	}
	token := r.FormValue("token")
	pending, ok := s.uploads.get(token)
	if !ok {
		s.renderFragment(w, "verdict-error", "this upload expired; please choose the file again")
		return
	}

	// Re-renders the mapping panel with a message, so a correctable mistake does
	// not cost the operator the form they were working in.
	retry := func(msg string) {
		p := buildPreview(token, pending.filename, pending.sheet, 0, -1)
		p.Error = msg
		s.renderFragment(w, "upload-preview", p)
	}

	emailCol, err := strconv.Atoi(r.FormValue("email_col"))
	if err != nil || emailCol < 0 {
		retry("Choose which column holds the email address.")
		return
	}
	labelCol, err := strconv.Atoi(r.FormValue("label_col"))
	if err != nil {
		labelCol = -1
	}

	extracted := pending.sheet.Extract(emailCol, labelCol)
	if len(extracted) == 0 {
		retry("No values found in the selected column — pick a different one.")
		return
	}

	// Guard against the operator picking the wrong column. Extract returns
	// whatever the cells contain, so without this a column of client names
	// would be submitted as addresses and burn a whole job on garbage.
	plausible := 0
	for _, e := range extracted {
		if ingest.LooksLikeEmail(e.Email) {
			plausible++
		}
	}
	if plausible == 0 {
		retry("That column does not look like email addresses — pick the column containing them.")
		return
	}

	rows := make([]jobs.Row, 0, len(extracted))
	for _, e := range extracted {
		rows = append(rows, jobs.Row{Label: e.Label, Email: e.Email})
	}

	job, err := s.cfg.Jobs.Submit(r.Context(), rows)
	if err != nil {
		retry("Could not submit the list: " + err.Error())
		return
	}
	s.uploads.drop(token)
	s.renderFragment(w, "job-created", job)
}

// handleJobExport streams a job's results as CSV or XLSX, preserving the client
// name — matching results back to the original sheet is the point of uploading
// one in the first place.
func (s *Server) handleJobExport(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Jobs == nil {
		http.Error(w, "bulk jobs are not enabled on this server", http.StatusNotImplemented)
		return
	}
	id := r.PathValue("id")
	format := r.PathValue("format")

	if _, err := s.cfg.Jobs.Get(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrJobNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "could not load job: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Exports are segregated by what the operator should do with each group;
	// handing back one undifferentiated dump would leave them to re-do the
	// segregation by hand.
	bucket := Bucket(r.URL.Query().Get("bucket"))
	if bucket == "" {
		bucket = BucketAll
	}
	if !validBucket(bucket) {
		http.Error(w, "unknown bucket; use safe, risky, undeliverable, skipped, retry, or all", http.StatusBadRequest)
		return
	}

	results, err := s.allResults(r.Context(), id)
	if err != nil {
		http.Error(w, "could not load results: "+err.Error(), http.StatusInternalServerError)
		return
	}
	results = filterBucket(results, bucket)

	name := id
	if bucket != BucketAll {
		name = id + "-" + string(bucket)
	}

	switch format {
	case "csv":
		writeResultsCSV(w, name, results)
	case "xlsx":
		writeResultsXLSX(w, name, results)
	default:
		http.Error(w, "unsupported export format; use csv or xlsx", http.StatusBadRequest)
	}
}

// allResults pages through a job's results. Exports are operator-initiated and
// bounded by the job size, so collecting them is acceptable here.
func (s *Server) allResults(ctx context.Context, id string) ([]store.Result, error) {
	var out []store.Result
	for cursor := 0; ; {
		page, next, err := s.cfg.Jobs.Results(ctx, id, cursor, exportPageSize)
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		if next == 0 || len(page) == 0 {
			return out, nil
		}
		cursor = next
	}
}

var exportHeader = []string{"client", "email", "status", "reason", "provider", "catch_all", "role", "disposable", "checked_at"}

func exportRow(r store.Result) []string {
	v := r.Verdict
	return []string{
		r.Label,
		v.Email,
		string(v.Status),
		string(v.SubStatus),
		v.Provider,
		strconv.FormatBool(v.Checks.CatchAll),
		strconv.FormatBool(v.Checks.Role),
		strconv.FormatBool(v.Checks.Disposable),
		v.CheckedAt.UTC().Format(time.RFC3339),
	}
}

func writeResultsCSV(w http.ResponseWriter, jobID string, results []store.Result) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="rcptto-%s.csv"`, jobID))

	cw := csv.NewWriter(w)
	defer cw.Flush()
	if err := cw.Write(exportHeader); err != nil {
		return
	}
	for _, r := range results {
		if err := cw.Write(exportRow(r)); err != nil {
			return
		}
	}
}

func writeResultsXLSX(w http.ResponseWriter, jobID string, results []store.Result) {
	f := excelize.NewFile()
	defer func() { _ = f.Close() }()
	sheet := f.GetSheetName(0)

	rows := make([][]string, 0, len(results)+1)
	rows = append(rows, exportHeader)
	for _, r := range results {
		rows = append(rows, exportRow(r))
	}
	for i, row := range rows {
		ref, err := excelize.CoordinatesToCellName(1, i+1)
		if err != nil {
			http.Error(w, "building spreadsheet", http.StatusInternalServerError)
			return
		}
		if err := f.SetSheetRow(sheet, ref, &row); err != nil {
			http.Error(w, "building spreadsheet", http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="rcptto-%s.xlsx"`, jobID))
	if _, err := f.WriteTo(w); err != nil {
		return
	}
}
