package ingest

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/xuri/excelize/v2"
)

func TestParseCSVWithHeader(t *testing.T) {
	in := "Client Name,Email\nAcme Ltd,a@acme.com\nBeta Inc,b@beta.com\n"
	s, err := Parse("list.csv", strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(s.Header) != 2 || s.Header[0] != "Client Name" {
		t.Errorf("header = %+v", s.Header)
	}
	if len(s.Rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(s.Rows))
	}

	emailCol, labelCol := s.DetectColumns()
	if emailCol != 1 || labelCol != 0 {
		t.Fatalf("detected email=%d label=%d, want 1/0", emailCol, labelCol)
	}
	rows := s.Extract(emailCol, labelCol)
	if len(rows) != 2 || rows[0].Label != "Acme Ltd" || rows[0].Email != "a@acme.com" {
		t.Errorf("rows = %+v", rows)
	}
}

// A file with no header row must not silently lose its first record.
func TestParseCSVWithoutHeader(t *testing.T) {
	in := "Acme Ltd,a@acme.com\nBeta Inc,b@beta.com\n"
	s, err := Parse("list.csv", strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if s.Header != nil {
		t.Errorf("header should be nil when the first row holds data, got %+v", s.Header)
	}
	if len(s.Rows) != 2 {
		t.Fatalf("rows = %d, want 2 (the first row must not be eaten as a header)", len(s.Rows))
	}
}

func TestDetectColumnsByContentNotHeaderOrder(t *testing.T) {
	// Email first, name second, and headers that say nothing useful.
	in := "col1,col2\nx@y.com,Acme\nz@w.com,Beta\n"
	s, _ := Parse("l.csv", strings.NewReader(in))

	emailCol, labelCol := s.DetectColumns()
	if emailCol != 0 {
		t.Errorf("email column = %d, want 0 (detected by content)", emailCol)
	}
	if labelCol != 1 {
		t.Errorf("label column = %d, want 1", labelCol)
	}
}

func TestDetectColumnsPrefersNamedHeader(t *testing.T) {
	// Two non-email columns; the one whose header names it should win.
	in := "ref,Company Name,Email\n001,Acme,a@acme.com\n002,Beta,b@beta.com\n"
	s, _ := Parse("l.csv", strings.NewReader(in))

	emailCol, labelCol := s.DetectColumns()
	if emailCol != 2 {
		t.Fatalf("email column = %d, want 2", emailCol)
	}
	if labelCol != 1 {
		t.Errorf("label column = %d, want 1 (the 'Company Name' header)", labelCol)
	}
}

func TestExtractSkipsRowsWithoutEmail(t *testing.T) {
	in := "Name,Email\nAcme,a@acme.com\nNoEmail,\nBeta,b@beta.com\n"
	s, _ := Parse("l.csv", strings.NewReader(in))
	rows := s.Extract(1, 0)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2 (the blank-email row must be skipped)", len(rows))
	}
}

func TestExtractWithoutLabelColumn(t *testing.T) {
	in := "a@acme.com\nb@beta.com\n"
	s, _ := Parse("l.csv", strings.NewReader(in))
	rows := s.Extract(0, -1)
	if len(rows) != 2 || rows[0].Label != "" || rows[0].Email != "a@acme.com" {
		t.Errorf("rows = %+v", rows)
	}
}

func TestRaggedRowsTolerated(t *testing.T) {
	// Real client sheets are frequently ragged; this must not error.
	in := "Name,Email,Extra\nAcme,a@acme.com\nBeta,b@beta.com,note\n"
	s, err := Parse("l.csv", strings.NewReader(in))
	if err != nil {
		t.Fatalf("ragged CSV should parse: %v", err)
	}
	if len(s.Rows) != 2 {
		t.Errorf("rows = %d, want 2", len(s.Rows))
	}
	if rows := s.Extract(1, 0); len(rows) != 2 {
		t.Errorf("extracted %d rows, want 2", len(rows))
	}
}

func TestBlankRowsSkipped(t *testing.T) {
	in := "Name,Email\nAcme,a@acme.com\n,\n\nBeta,b@beta.com\n"
	s, _ := Parse("l.csv", strings.NewReader(in))
	if len(s.Rows) != 2 {
		t.Errorf("rows = %d, want 2 (blank rows dropped)", len(s.Rows))
	}
}

func TestEmptyFileIsAnError(t *testing.T) {
	if _, err := Parse("l.csv", strings.NewReader("")); !errors.Is(err, ErrNoRows) {
		t.Errorf("err = %v, want ErrNoRows", err)
	}
	// Header only, no data.
	if _, err := Parse("l.csv", strings.NewReader("Name,Email\n")); !errors.Is(err, ErrNoRows) {
		t.Errorf("header-only err = %v, want ErrNoRows", err)
	}
}

func TestUnsupportedExtension(t *testing.T) {
	if _, err := Parse("list.pdf", strings.NewReader("x")); err == nil {
		t.Error("expected an error for an unsupported file type")
	}
}

func TestPreviewCaps(t *testing.T) {
	var b strings.Builder
	b.WriteString("Name,Email\n")
	for i := 0; i < 20; i++ {
		b.WriteString("Client,x@y.com\n")
	}
	s, _ := Parse("l.csv", strings.NewReader(b.String()))
	if got := len(s.Preview()); got != PreviewRows {
		t.Errorf("preview rows = %d, want %d", got, PreviewRows)
	}
}

// buildXLSX writes a real workbook in memory so the XLSX path is exercised
// against the actual format rather than a stub.
func buildXLSX(t *testing.T, rows [][]string) *bytes.Reader {
	t.Helper()
	f := excelize.NewFile()
	defer func() { _ = f.Close() }()
	sheet := f.GetSheetName(0)
	for i, row := range rows {
		for j, cell := range row {
			ref, err := excelize.CoordinatesToCellName(j+1, i+1)
			if err != nil {
				t.Fatalf("cell name: %v", err)
			}
			if err := f.SetCellValue(sheet, ref, cell); err != nil {
				t.Fatalf("set cell: %v", err)
			}
		}
	}
	buf, err := f.WriteToBuffer()
	if err != nil {
		t.Fatalf("write xlsx: %v", err)
	}
	return bytes.NewReader(buf.Bytes())
}

func TestParseXLSX(t *testing.T) {
	r := buildXLSX(t, [][]string{
		{"Client Name", "Email"},
		{"Acme Ltd", "a@acme.com"},
		{"Beta Inc", "b@beta.com"},
	})

	s, err := Parse("list.xlsx", r)
	if err != nil {
		t.Fatalf("Parse xlsx: %v", err)
	}
	if len(s.Header) != 2 || s.Header[1] != "Email" {
		t.Errorf("header = %+v", s.Header)
	}
	emailCol, labelCol := s.DetectColumns()
	rows := s.Extract(emailCol, labelCol)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	if rows[0].Label != "Acme Ltd" || rows[0].Email != "a@acme.com" {
		t.Errorf("row[0] = %+v", rows[0])
	}
	if rows[1].Label != "Beta Inc" || rows[1].Email != "b@beta.com" {
		t.Errorf("row[1] = %+v", rows[1])
	}
}

func TestParseXLSXNoHeader(t *testing.T) {
	r := buildXLSX(t, [][]string{
		{"Acme Ltd", "a@acme.com"},
		{"Beta Inc", "b@beta.com"},
	})
	s, err := Parse("list.xlsx", r)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(s.Rows) != 2 {
		t.Errorf("rows = %d, want 2", len(s.Rows))
	}
}

func TestParseXLSXCorruptFile(t *testing.T) {
	if _, err := Parse("bad.xlsx", strings.NewReader("not a zip archive")); err == nil {
		t.Error("expected an error for a corrupt XLSX")
	}
}

func TestLooksLikeEmail(t *testing.T) {
	good := []string{"a@b.com", " user@example.co.uk "}
	bad := []string{"", "no-at-sign", "@nolocal.com", "trailing@", "a@b", "two words@x.com"}
	for _, s := range good {
		if !looksLikeEmail(s) {
			t.Errorf("looksLikeEmail(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if looksLikeEmail(s) {
			t.Errorf("looksLikeEmail(%q) = true, want false", s)
		}
	}
}
