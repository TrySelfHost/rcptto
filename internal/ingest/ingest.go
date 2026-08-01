// Package ingest reads address lists out of uploaded spreadsheets.
//
// Real client lists arrive as CSV or XLSX with arbitrary columns, so parsing is
// split from interpretation: Parse produces a Sheet of raw cells, DetectColumns
// guesses which column holds the address and which holds the client name, and
// Extract turns a confirmed mapping into rows. That ordering exists so the
// dashboard can show a preview and let the operator correct the guess before
// anything is verified — a mis-detected column would otherwise send a whole
// list of garbage at real mail servers.
package ingest

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/xuri/excelize/v2"
)

// Limits guarding against malformed or hostile uploads.
const (
	// MaxRows caps how many data rows a single upload may contain.
	MaxRows = 200_000
	// MaxColumns caps columns read per row.
	MaxColumns = 64
	// PreviewRows is how many rows the dashboard shows before submission.
	PreviewRows = 5
)

// ErrNoRows reports a file that parsed correctly but contained no data.
var ErrNoRows = errors.New("ingest: the file contains no data rows")

// Row is one address to verify, with the label carried alongside it.
type Row struct {
	// Label is the client name (or any identifying text) from the sheet. It is
	// carried through verification untouched so results can be matched back to
	// the original list.
	Label string
	// Email is the address to verify.
	Email string
}

// Sheet is a parsed spreadsheet: an optional header row plus raw data rows.
type Sheet struct {
	// Header holds the first row when it looks like column titles.
	Header []string
	// Rows holds the data rows, excluding the header.
	Rows [][]string
}

// Parse reads a CSV or XLSX file, choosing the reader by file extension.
func Parse(filename string, r io.Reader) (*Sheet, error) {
	switch strings.ToLower(filepath.Ext(filename)) {
	case ".csv", ".txt", ".tsv":
		return parseCSV(r)
	case ".xlsx", ".xlsm":
		return parseXLSX(r)
	default:
		return nil, fmt.Errorf("ingest: unsupported file type %q; upload a .csv or .xlsx", filepath.Ext(filename))
	}
}

func parseCSV(r io.Reader) (*Sheet, error) {
	cr := csv.NewReader(r)
	// Client lists are frequently ragged; tolerate varying column counts rather
	// than rejecting an otherwise usable file.
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true

	var rows [][]string
	for len(rows) <= MaxRows {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("ingest: reading CSV: %w", err)
		}
		if len(rec) > MaxColumns {
			rec = rec[:MaxColumns]
		}
		if isBlank(rec) {
			continue
		}
		rows = append(rows, rec)
	}
	return newSheet(rows)
}

func parseXLSX(r io.Reader) (*Sheet, error) {
	f, err := excelize.OpenReader(r)
	if err != nil {
		return nil, fmt.Errorf("ingest: reading XLSX: %w", err)
	}
	defer func() { _ = f.Close() }()

	sheets := f.GetSheetList()
	if len(sheets) == 0 {
		return nil, ErrNoRows
	}
	// Only the first worksheet is read; a client list spread across tabs is
	// ambiguous, and silently concatenating them would be a surprising default.
	raw, err := f.GetRows(sheets[0])
	if err != nil {
		return nil, fmt.Errorf("ingest: reading worksheet %q: %w", sheets[0], err)
	}

	rows := make([][]string, 0, len(raw))
	for _, rec := range raw {
		if len(rows) >= MaxRows {
			break
		}
		if len(rec) > MaxColumns {
			rec = rec[:MaxColumns]
		}
		if isBlank(rec) {
			continue
		}
		rows = append(rows, rec)
	}
	return newSheet(rows)
}

// newSheet splits an optional header off the parsed rows.
func newSheet(rows [][]string) (*Sheet, error) {
	if len(rows) == 0 {
		return nil, ErrNoRows
	}
	s := &Sheet{Rows: rows}
	// A first row containing no address is treated as column titles. This is
	// more reliable than matching header words, which vary by language and by
	// however the client happened to label their spreadsheet.
	if !rowHasEmail(rows[0]) {
		s.Header = rows[0]
		s.Rows = rows[1:]
	}
	if len(s.Rows) == 0 {
		return nil, ErrNoRows
	}
	return s, nil
}

// DetectColumns guesses which column holds the email address and which holds
// the client name. emailCol is -1 when no column looks like addresses.
//
// Detection is by content rather than header text: the column where the most
// cells look like addresses wins. The label column is then the first other
// column with meaningful text, preferring one whose header mentions a name.
func (s *Sheet) DetectColumns() (emailCol, labelCol int) {
	width := s.width()
	if width == 0 {
		return -1, -1
	}

	emailCol, labelCol = -1, -1
	bestHits := 0
	for c := 0; c < width; c++ {
		hits := 0
		for _, row := range s.Rows {
			if c < len(row) && looksLikeEmail(row[c]) {
				hits++
			}
		}
		if hits > bestHits {
			bestHits, emailCol = hits, c
		}
	}
	if emailCol == -1 {
		return -1, -1
	}

	// Prefer a column whose header names it.
	for c, h := range s.Header {
		if c == emailCol || c >= width {
			continue
		}
		if headerLooksLikeName(h) {
			return emailCol, c
		}
	}
	// Otherwise the first other column with any non-empty text.
	for c := 0; c < width; c++ {
		if c == emailCol {
			continue
		}
		for _, row := range s.Rows {
			if c < len(row) && strings.TrimSpace(row[c]) != "" {
				return emailCol, c
			}
		}
	}
	return emailCol, -1
}

// Extract turns a column mapping into rows, skipping any row whose email cell
// is empty. A labelCol of -1 yields rows with an empty Label.
func (s *Sheet) Extract(emailCol, labelCol int) []Row {
	if emailCol < 0 {
		return nil
	}
	out := make([]Row, 0, len(s.Rows))
	for _, row := range s.Rows {
		if emailCol >= len(row) {
			continue
		}
		email := strings.TrimSpace(row[emailCol])
		if email == "" {
			continue
		}
		var label string
		if labelCol >= 0 && labelCol < len(row) {
			label = strings.TrimSpace(row[labelCol])
		}
		out = append(out, Row{Label: label, Email: email})
	}
	return out
}

// Preview returns up to PreviewRows data rows, for confirming the mapping
// before a list is submitted.
func (s *Sheet) Preview() [][]string {
	if len(s.Rows) <= PreviewRows {
		return s.Rows
	}
	return s.Rows[:PreviewRows]
}

// width reports the widest row, so ragged sheets are handled consistently.
func (s *Sheet) width() int {
	w := len(s.Header)
	for _, row := range s.Rows {
		if len(row) > w {
			w = len(row)
		}
	}
	if w > MaxColumns {
		w = MaxColumns
	}
	return w
}

func rowHasEmail(row []string) bool {
	for _, c := range row {
		if looksLikeEmail(c) {
			return true
		}
	}
	return false
}

// looksLikeEmail is a deliberately loose check used only to find the right
// column. Real validation happens in the verification funnel.
func looksLikeEmail(s string) bool {
	s = strings.TrimSpace(s)
	at := strings.IndexByte(s, '@')
	if at <= 0 || at == len(s)-1 || strings.ContainsAny(s, " \t") {
		return false
	}
	return strings.Contains(s[at+1:], ".")
}

func headerLooksLikeName(h string) bool {
	h = strings.ToLower(strings.TrimSpace(h))
	for _, kw := range []string{"name", "client", "company", "contact", "customer", "organisation", "organization"} {
		if strings.Contains(h, kw) {
			return true
		}
	}
	return false
}

func isBlank(rec []string) bool {
	for _, c := range rec {
		if strings.TrimSpace(c) != "" {
			return false
		}
	}
	return true
}
