package web

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/tryselfhost/rcptto/internal/settings"
)

// SettingsManager loads, validates, and applies runtime configuration.
type SettingsManager interface {
	// Current returns the settings in force.
	Current() settings.Settings
	// Apply validates, persists, and activates new settings.
	Apply(ctx context.Context, s settings.Settings) error
}

// settingsField describes one control, so the guidance lives beside the value
// rather than being buried in documentation the operator will not read.
type settingsField struct {
	Name    string
	Label   string
	Value   string
	Help    string
	Max     string
	Danger  bool
	Checked bool
	IsBool  bool
}

type settingsView struct {
	Performance []settingsField
	Reputation  []settingsField
	Error       string
	Saved       bool
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Settings == nil {
		http.Error(w, "settings are not enabled on this server", http.StatusNotImplemented)
		return
	}
	s.renderPage(w, "rcpttō — Settings", "content-settings", buildSettingsView(s.cfg.Settings.Current(), "", false))
}

func (s *Server) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Settings == nil {
		http.Error(w, "settings are not enabled on this server", http.StatusNotImplemented)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderFragment(w, "settings-form", buildSettingsView(s.cfg.Settings.Current(), "Invalid form submission.", false))
		return
	}

	current := s.cfg.Settings.Current()
	next := settings.Settings{
		ProbeRate:           formFloat(r, "probe_rate", current.ProbeRate),
		ProbeBurst:          formFloat(r, "probe_burst", current.ProbeBurst),
		JobConcurrency:      formInt(r, "job_concurrency", current.JobConcurrency),
		MaxEmailsPerJob:     formInt(r, "max_emails_per_job", current.MaxEmailsPerJob),
		DetectCatchAll:      r.FormValue("detect_catch_all") != "",
		QuarantineThreshold: formInt(r, "quarantine_threshold", current.QuarantineThreshold),
		CircuitThreshold:    formInt(r, "circuit_threshold", current.CircuitThreshold),
	}

	if err := s.cfg.Settings.Apply(r.Context(), next); err != nil {
		// Show the submitted values back with the reason, so the operator can
		// correct one field rather than re-entering the whole form.
		msg := err.Error()
		if errors.Is(err, settings.ErrInvalid) {
			msg = "Rejected: " + msg
		}
		s.renderFragment(w, "settings-form", buildSettingsView(next, msg, false))
		return
	}
	s.renderFragment(w, "settings-form", buildSettingsView(s.cfg.Settings.Current(), "", true))
}

func buildSettingsView(s settings.Settings, errMsg string, saved bool) settingsView {
	return settingsView{
		Error: errMsg,
		Saved: saved,
		Performance: []settingsField{
			{
				Name: "probe_rate", Label: "Probe rate", Value: strconv.FormatFloat(s.ProbeRate, 'f', -1, 64),
				Max:    strconv.FormatFloat(settings.MaxProbeRate, 'f', -1, 64),
				Danger: true,
				Help: "SMTP probes per second, per destination mail server. This is the " +
					"main protection against a list concentrated on one domain looking like " +
					"an attack. Raising it increases the risk of being blocked.",
			},
			{
				Name: "probe_burst", Label: "Probe burst", Value: strconv.FormatFloat(s.ProbeBurst, 'f', -1, 64),
				Max:    strconv.FormatFloat(settings.MaxProbeBurst, 'f', -1, 64),
				Danger: true,
				Help:   "How many probes may go back-to-back to one destination after an idle period.",
			},
			{
				Name: "job_concurrency", Label: "Job concurrency", Value: strconv.Itoa(s.JobConcurrency),
				Max: strconv.Itoa(settings.MaxJobConcurrency),
				Help: "Addresses verified in parallel within a job. Applies to jobs started " +
					"after saving; the per-destination rate limit still applies regardless.",
			},
			{
				Name: "max_emails_per_job", Label: "Maximum addresses per job", Value: strconv.Itoa(s.MaxEmailsPerJob),
				Max:  strconv.Itoa(settings.MaxEmailsPerJobCeiling),
				Help: "Largest single upload accepted.",
			},
			{
				Name: "detect_catch_all", Label: "Detect catch-all domains", IsBool: true, Checked: s.DetectCatchAll,
				Help: "Probes a random address to tell a genuine mailbox from a domain that " +
					"accepts everything. Accurate, but costs a second probe per accepted address.",
			},
		},
		Reputation: []settingsField{
			{
				Name: "quarantine_threshold", Label: "Quarantine threshold", Value: strconv.Itoa(s.QuarantineThreshold),
				Max: strconv.Itoa(settings.MaxThreshold),
				Help: "Consecutive block signals before an egress identity is withdrawn. " +
					"Lower is more cautious — it withdraws a degrading IP sooner.",
			},
			{
				Name: "circuit_threshold", Label: "Circuit-breaker threshold", Value: strconv.Itoa(s.CircuitThreshold),
				Max: strconv.Itoa(settings.MaxThreshold),
				Help: "Failures against one destination before that identity stops probing it. " +
					"Other destinations are unaffected.",
			},
		},
	}
}

func formFloat(r *http.Request, key string, def float64) float64 {
	v, err := strconv.ParseFloat(r.FormValue(key), 64)
	if err != nil {
		return def
	}
	return v
}

func formInt(r *http.Request, key string, def int) int {
	v, err := strconv.Atoi(r.FormValue(key))
	if err != nil {
		return def
	}
	return v
}
