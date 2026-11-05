package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/locktera/autoattest/attest"
)

func TestRootCommandWiring(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr bool
	}{
		{"help", []string{"--help"}, "confidential compute attestation", false},
		{"version", []string{"--version"}, "dev", false},
		{"unknown flag", []string{"--bogus"}, "", true},
		{"no positional args", []string{"extra"}, "", true},
		{"bad config file", []string{"--config", "/nonexistent/x.yaml"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			root := NewRootCmd()
			root.SetOut(buf)
			root.SetErr(buf)
			root.SetArgs(tt.args)
			err := root.ExecuteContext(t.Context())
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !strings.Contains(buf.String(), tt.want) {
				t.Errorf("output %q missing %q", buf.String(), tt.want)
			}
		})
	}
}

func TestJSONOutput(t *testing.T) {
	safe := func(context.Context, attest.Config) (*attest.Report, error) {
		return &attest.Report{Safe: true, Nonce: "abcd", Checks: []attest.Check{{Section: "s", Name: "n", Status: attest.StatusPass}}}, nil
	}
	unsafe := func(context.Context, attest.Config) (*attest.Report, error) {
		return &attest.Report{Safe: false, Checks: []attest.Check{{Section: "s", Name: "n", Status: attest.StatusFail}}}, nil
	}
	broken := func(context.Context, attest.Config) (*attest.Report, error) {
		return nil, errors.New("nonce generation failed")
	}
	tests := []struct {
		name      string
		args      []string
		run       runFunc
		wantSafe  bool
		wantErr   error
		wantError string
	}{
		{"long flag", []string{"--json"}, safe, true, nil, ""},
		{"short flag", []string{"-j"}, safe, true, nil, ""},
		{"env var", nil, safe, true, nil, ""},
		{"not safe", []string{"-j"}, unsafe, false, ErrNotSafe, ""},
		{"run error still emits json", []string{"-j"}, broken, false, nil, "nonce generation failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.args == nil {
				t.Setenv("AUTOATTEST_JSON", "true")
			}
			stdout, stderr := new(bytes.Buffer), new(bytes.Buffer)
			root := newRootCmd(tt.run)
			root.SetOut(stdout)
			root.SetErr(stderr)
			root.SetArgs(append([]string{"--config", writeEmptyConfig(t)}, tt.args...))
			err := root.ExecuteContext(t.Context())
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if tt.wantError != "" && err == nil {
				t.Fatal("expected run error to be returned for a non-zero exit")
			}

			var got attest.Report
			dec := json.NewDecoder(stdout)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&got); err != nil {
				t.Fatalf("stdout is not a JSON report: %v\n%s", err, stdout.String())
			}
			if dec.More() {
				t.Fatal("stdout contains more than one JSON document")
			}
			if got.Safe != tt.wantSafe {
				t.Errorf("safe = %v, want %v", got.Safe, tt.wantSafe)
			}
			if got.Error != tt.wantError {
				t.Errorf("error = %q, want %q", got.Error, tt.wantError)
			}
		})
	}
}

func TestTextOutputByDefault(t *testing.T) {
	stdout := new(bytes.Buffer)
	root := newRootCmd(func(context.Context, attest.Config) (*attest.Report, error) {
		return &attest.Report{Safe: true, Checks: []attest.Check{{Status: attest.StatusPass}}}, nil
	})
	root.SetOut(stdout)
	root.SetArgs([]string{"--config", writeEmptyConfig(t)})
	if err := root.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "VERDICT: SAFE") || json.Valid(stdout.Bytes()) {
		t.Fatalf("expected text report, got %q", stdout.String())
	}
}

// writeEmptyConfig isolates tests from any ~/.autoattest.yaml on the machine.
func writeEmptyConfig(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
