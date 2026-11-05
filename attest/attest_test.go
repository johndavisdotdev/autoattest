package attest

import (
	"context"
	"crypto/sha512"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type fakeQuotes struct {
	quote []byte
	err   error
}

func (f fakeQuotes) Quote(context.Context, [64]byte) ([]byte, error) { return f.quote, f.err }

func TestReportDataIsSHA512OfNonce(t *testing.T) {
	n := []byte("0123456789abcdef0123456789abcdef")
	if reportDataFor(n) != sha512.Sum512(n) {
		t.Fatal("report_data must be SHA-512(nonce)")
	}
}

func TestTDXFailures(t *testing.T) {
	dev := filepath.Join(t.TempDir(), "tdx_guest")
	if err := os.WriteFile(dev, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		device string
		quotes QuoteProvider
		check  string
	}{
		{"no tdx device", filepath.Join(t.TempDir(), "missing"), fakeQuotes{}, "TDX guest device"},
		{"permission denied", dev, fakeQuotes{err: os.ErrPermission}, "Generate TD quote"},
		{"not a tdx quote", dev, fakeQuotes{quote: []byte{0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 1, 2, 3}}, "Quote header"},
		{"garbage tdx quote", dev, fakeQuotes{quote: append([]byte{0x04, 0x00, 0x02, 0x00, 0x81, 0x00}, make([]byte, 100)...)}, "Parse quote"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &runner{cfg: withDefaults(Config{TDXDevice: tt.device}), report: newReport(), nonce: make([]byte, 32), quotes: tt.quotes}
			r.attestTDX(t.Context())
			requireStatus(t, r.report, tt.check, StatusFail)
		})
	}
}

func TestRunWithIsNotSafeWhenAnythingFails(t *testing.T) {
	rep, err := RunWith(t.Context(), Config{TDXDevice: "/nonexistent"}, Deps{
		Quotes: fakeQuotes{err: errors.New("unused")},
		GPUs:   fakeGPUs{state: goodCC},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Safe {
		t.Fatal("report must not be safe")
	}
	if len(rep.Failures()) == 0 {
		t.Fatal("expected failures")
	}
}

func TestFinalizeRequiresAPass(t *testing.T) {
	r := newReport()
	r.info("s", "n", "")
	r.finalize()
	if r.Safe {
		t.Fatal("an empty/all-info report must not be safe")
	}
}

// TestIntegration runs the real attestation. It needs a TDX guest with a
// CC-mode NVIDIA GPU, root, and network access:
//
//	sudo AUTOATTEST_INTEGRATION=1 go test ./attest -run Integration -v
func TestIntegration(t *testing.T) {
	if os.Getenv("AUTOATTEST_INTEGRATION") == "" {
		t.Skip("set AUTOATTEST_INTEGRATION=1 to run against real hardware")
	}
	rep, err := Run(t.Context(), Config{})
	if err != nil {
		t.Fatal(err)
	}
	rep.WriteText(t.Output(), true)
	if !rep.Safe {
		t.Fatalf("not safe: %+v", rep.Failures())
	}
}
