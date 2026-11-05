package attest

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// Status is the outcome of a single check.
type Status string

const (
	StatusPass Status = "PASS"
	StatusFail Status = "FAIL"
	StatusWarn Status = "WARN"
	StatusInfo Status = "INFO"
)

// Check is one line item in the attestation report.
type Check struct {
	Section string `json:"section"`
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Detail  string `json:"detail,omitempty"`
}

// Measurements are values worth recording or pinning in policy.
type Measurements struct {
	MRTD      string   `json:"mrtd,omitempty"`
	RTMRs     []string `json:"rtmrs,omitempty"`
	MRSeam    string   `json:"mrseam,omitempty"`
	TDAttrs   string   `json:"td_attributes,omitempty"`
	XFAM      string   `json:"xfam,omitempty"`
	TeeTCBSVN string   `json:"tee_tcb_svn,omitempty"`
}

// GPUInfo summarises one attested GPU.
type GPUInfo struct {
	Index         int    `json:"index"`
	UUID          string `json:"uuid"`
	Name          string `json:"name"`
	Arch          string `json:"arch"`
	DriverVersion string `json:"driver_version,omitempty"`
	VBIOSVersion  string `json:"vbios_version,omitempty"`
}

// Report is the full result of an attestation run.
type Report struct {
	Started  time.Time    `json:"started"`
	Duration string       `json:"duration"`
	Nonce    string       `json:"nonce"`
	Checks   []Check      `json:"checks"`
	TDX      Measurements `json:"tdx,omitzero"`
	GPUs     []GPUInfo    `json:"gpus,omitempty"`
	Safe     bool         `json:"safe"`
	// Error is set when the run could not be completed (e.g. bad config).
	Error string `json:"error,omitempty"`
}

func (r *Report) add(section, name string, s Status, format string, args ...any) {
	r.Checks = append(r.Checks, Check{
		Section: section,
		Name:    name,
		Status:  s,
		Detail:  fmt.Sprintf(format, args...),
	})
}

func (r *Report) pass(section, name, format string, args ...any) {
	r.add(section, name, StatusPass, format, args...)
}

func (r *Report) fail(section, name, format string, args ...any) {
	r.add(section, name, StatusFail, format, args...)
}

func (r *Report) info(section, name, format string, args ...any) {
	r.add(section, name, StatusInfo, format, args...)
}

func (r *Report) warn(section, name, format string, args ...any) {
	r.add(section, name, StatusWarn, format, args...)
}

// Failures returns every failed check.
func (r *Report) Failures() []Check {
	var out []Check
	for _, c := range r.Checks {
		if c.Status == StatusFail {
			out = append(out, c)
		}
	}
	return out
}

// finalize computes the verdict. A run is only safe if at least one check
// passed and none failed.
func (r *Report) finalize() {
	passed := false
	for _, c := range r.Checks {
		if c.Status == StatusPass {
			passed = true
		}
	}
	r.Safe = passed && len(r.Failures()) == 0
	r.Duration = time.Since(r.Started).Round(time.Millisecond).String()
}

// WriteJSON writes the report as indented JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText writes a human-readable report.
func (r *Report) WriteText(w io.Writer, verbose bool) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Confidential Compute Attestation Report\n")
	fmt.Fprintf(&b, "  started: %s   duration: %s\n", r.Started.Format(time.RFC3339), r.Duration)
	fmt.Fprintf(&b, "  nonce:   %s\n", r.Nonce)

	section := ""
	for _, c := range r.Checks {
		if c.Section != section {
			section = c.Section
			fmt.Fprintf(&b, "\n%s\n", section)
		}
		if c.Status == StatusInfo && !verbose {
			continue
		}
		fmt.Fprintf(&b, "  %s %-34s %s\n", symbol(c.Status), c.Name, c.Detail)
	}

	if verbose && r.TDX.MRTD != "" {
		fmt.Fprintf(&b, "\nTD measurements\n")
		fmt.Fprintf(&b, "  MRTD:    %s\n", r.TDX.MRTD)
		for i, m := range r.TDX.RTMRs {
			fmt.Fprintf(&b, "  RTMR[%d]: %s\n", i, m)
		}
		fmt.Fprintf(&b, "  MRSEAM:  %s\n", r.TDX.MRSeam)
	}

	fmt.Fprintln(&b)
	if r.Safe {
		fmt.Fprintf(&b, "VERDICT: SAFE — TD and all GPUs are attested and under Confidential Compute protection.\n")
	} else {
		fmt.Fprintf(&b, "VERDICT: NOT SAFE — %d check(s) failed:\n", len(r.Failures()))
		for _, f := range r.Failures() {
			fmt.Fprintf(&b, "  - [%s] %s: %s\n", f.Section, f.Name, f.Detail)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func symbol(s Status) string {
	switch s {
	case StatusPass:
		return "[PASS]"
	case StatusFail:
		return "[FAIL]"
	case StatusWarn:
		return "[WARN]"
	default:
		return "[INFO]"
	}
}
