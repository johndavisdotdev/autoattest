// Package attest performs end-to-end confidential compute attestation of an
// Intel TDX confidential VM with attached NVIDIA GPUs, following
// https://docs.voltagegpu.com/pods/confidential-vm.
//
// One fresh 32-byte nonce binds the whole run:
//   - the TDX quote carries SHA-512(nonce) as report_data and is verified
//     against the pinned Intel SGX Root CA with collateral from Intel PCS;
//   - each GPU attestation report is requested with the nonce, its signature
//     and certificate chain are verified locally against the pinned NVIDIA
//     Device Identity CA, and it is then verified remotely by NVIDIA NRAS,
//     whose signed EAT token must echo the same nonce.
package attest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Config controls an attestation run.
type Config struct {
	NRASURL        string        `mapstructure:"nras-url"`
	ClaimsVersion  string        `mapstructure:"claims-version"`
	NRASServiceKey string        `mapstructure:"nras-service-key"`
	Timeout        time.Duration `mapstructure:"timeout"`
	TDXDevice      string        `mapstructure:"tdx-device"`
	ConfigfsRoot   string        `mapstructure:"configfs-root"`
	EvidenceDir    string        `mapstructure:"evidence-dir"`
}

// Default configuration values.
const (
	DefaultNRASURL       = "https://nras.attestation.nvidia.com/v3/attest/gpu"
	DefaultClaimsVersion = "2.0"
	DefaultTimeout       = 2 * time.Minute
	DefaultTDXDevice     = "/dev/tdx_guest"
	DefaultConfigfsRoot  = "/sys/kernel/config/tsm/report"
)

// Deps are the external systems a run talks to. Zero values select the real
// implementations.
type Deps struct {
	Quotes     QuoteProvider
	GPUs       GPUSource
	HTTPClient *http.Client
	Nonce      []byte // for tests only; must be 32 bytes
}

// Evidence is the raw material collected during a run.
type Evidence struct {
	TDXQuote     []byte
	GPUs         []GPUEvidence
	NRASResponse []byte
}

type runner struct {
	cfg        Config
	report     *Report
	nonce      []byte
	quotes     QuoteProvider
	gpus       GPUSource
	httpClient *http.Client
	evidence   Evidence
}

func (r *runner) gpuNonce() [32]byte {
	var n [32]byte
	copy(n[:], r.nonce)
	return n
}

// Run performs a full attestation using the real TDX and NVML providers.
func Run(ctx context.Context, cfg Config) (*Report, error) {
	return RunWith(ctx, cfg, Deps{})
}

// RunWith performs a full attestation with injectable dependencies. A
// returned error means the run could not be carried out; a completed run
// that found problems returns a Report with Safe == false and a nil error.
func RunWith(ctx context.Context, cfg Config, deps Deps) (*Report, error) {
	cfg = withDefaults(cfg)
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	nonce := deps.Nonce
	if nonce == nil {
		nonce = make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("generating nonce: %w", err)
		}
	}
	if len(nonce) != 32 {
		return nil, errors.New("nonce must be 32 bytes")
	}

	r := &runner{
		cfg:        cfg,
		report:     &Report{Started: time.Now(), Nonce: hex.EncodeToString(nonce)},
		nonce:      nonce,
		quotes:     deps.Quotes,
		gpus:       deps.GPUs,
		httpClient: deps.HTTPClient,
	}
	if r.quotes == nil {
		r.quotes = ConfigfsQuoteProvider{Root: cfg.ConfigfsRoot}
	}
	if r.httpClient == nil {
		r.httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	r.attestTDX(ctx)

	if r.gpus == nil {
		src, err := OpenNVML()
		if err != nil {
			r.report.fail(sectionGPU, "NVML", "%v (is the NVIDIA driver loaded?)", err)
		} else {
			defer src.Close()
			r.gpus = src
		}
	}
	if r.gpus != nil {
		evs := r.attestGPUs()
		r.evidence.GPUs = evs
		r.attestNRAS(ctx, evs)
	} else {
		r.report.fail(sectionNRAS, "Remote GPU attestation", "skipped: no GPU evidence collected")
	}

	r.report.finalize()

	if cfg.EvidenceDir != "" {
		if err := writeEvidence(cfg.EvidenceDir, r.report, r.evidence); err != nil {
			return r.report, fmt.Errorf("saving evidence: %w", err)
		}
	}
	return r.report, nil
}

func withDefaults(c Config) Config {
	if c.NRASURL == "" {
		c.NRASURL = DefaultNRASURL
	}
	if c.ClaimsVersion == "" {
		c.ClaimsVersion = DefaultClaimsVersion
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.TDXDevice == "" {
		c.TDXDevice = DefaultTDXDevice
	}
	if c.ConfigfsRoot == "" {
		c.ConfigfsRoot = DefaultConfigfsRoot
	}
	return c
}

func writeEvidence(dir string, rep *Report, ev Evidence) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	write := func(name string, data []byte) error {
		if len(data) == 0 {
			return nil
		}
		return os.WriteFile(filepath.Join(dir, name), data, 0o600)
	}
	if err := write("tdx-quote.bin", ev.TDXQuote); err != nil {
		return err
	}
	for _, g := range ev.GPUs {
		if err := write(fmt.Sprintf("gpu-%d-report.bin", g.Info.Index), g.Report); err != nil {
			return err
		}
		if err := write(fmt.Sprintf("gpu-%d-certchain.pem", g.Info.Index), g.CertChainPEM); err != nil {
			return err
		}
	}
	if err := write("nras-response.json", ev.NRASResponse); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "report.json"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := rep.WriteJSON(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
