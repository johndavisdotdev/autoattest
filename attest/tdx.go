package attest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
)

const (
	sectionTDX = "Intel TDX (confidential VM)"

	// tdxQuoteHeaderPrefix is version 4, attestation key type ECDSA-P256,
	// TEE type 0x81 (TDX), per the VoltageGPU docs and Intel's quote spec.
	reportDataOffset = 568 // 48-byte header + 520-byte offset into the TD quote body
	tdAttrDebugBit   = 0x01
)

var tdxQuoteHeaderPrefix = []byte{0x04, 0x00, 0x02, 0x00, 0x81, 0x00}

// QuoteProvider produces a raw TDX quote binding the given report data.
type QuoteProvider interface {
	Quote(ctx context.Context, reportData [64]byte) ([]byte, error)
}

// ConfigfsQuoteProvider generates quotes via the Linux configfs-tsm ABI at
// /sys/kernel/config/tsm/report.
type ConfigfsQuoteProvider struct {
	Root string
}

// configfsMu serializes quote generation within this process; the kernel
// rejects concurrent configfs-tsm requests with EINVAL.
var configfsMu sync.Mutex

// Quote implements QuoteProvider. Per VoltageGPU guidance, it retries only on
// EINVAL (concurrent request) and fails fast on anything else.
func (p ConfigfsQuoteProvider) Quote(ctx context.Context, reportData [64]byte) ([]byte, error) {
	configfsMu.Lock()
	defer configfsMu.Unlock()

	const attempts = 5
	var lastErr error
	for i := range attempts {
		q, err := p.quoteOnce(reportData)
		if err == nil {
			return q, nil
		}
		if !errors.Is(err, syscall.EINVAL) {
			return nil, err
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(50*(i+1)) * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("configfs-tsm busy after %d attempts: %w", attempts, lastErr)
}

func (p ConfigfsQuoteProvider) quoteOnce(reportData [64]byte) ([]byte, error) {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return nil, err
	}
	dir := filepath.Join(p.Root, "autoattest-"+hex.EncodeToString(suffix[:]))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating configfs report entry: %w", err)
	}
	defer os.Remove(dir)

	if provider, err := os.ReadFile(filepath.Join(dir, "provider")); err == nil {
		if got := strings.TrimSpace(string(provider)); got != "tdx_guest" {
			return nil, fmt.Errorf("configfs-tsm provider is %q, want tdx_guest", got)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "inblob"), reportData[:], 0); err != nil {
		return nil, fmt.Errorf("writing inblob: %w", err)
	}
	quote, err := os.ReadFile(filepath.Join(dir, "outblob"))
	if err != nil {
		return nil, fmt.Errorf("reading outblob: %w", err)
	}
	// generation must be exactly 1: our single write. Anything else means
	// another writer raced us and the quote may not carry our report data.
	gen, err := os.ReadFile(filepath.Join(dir, "generation"))
	if err == nil && strings.TrimSpace(string(gen)) != "1" {
		return nil, fmt.Errorf("configfs generation is %s, expected 1 (concurrent writer): %w",
			strings.TrimSpace(string(gen)), syscall.EINVAL)
	}
	return quote, nil
}

// pcsGetter fetches Intel PCS collateral, honouring the context and retrying
// transient failures. It implements go-tdx-guest's trust.HTTPSGetter.
type pcsGetter struct {
	ctx    context.Context
	client *http.Client
}

func (g pcsGetter) Get(url string) (map[string][]string, []byte, error) {
	var lastErr error
	for attempt := range 3 {
		if attempt > 0 {
			select {
			case <-g.ctx.Done():
				return nil, nil, g.ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(g.ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, nil, err
		}
		resp, err := g.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusOK {
			return resp.Header, body, nil
		}
		lastErr = fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
		if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			break
		}
	}
	return nil, nil, lastErr
}

// reportDataFor returns the 64-byte TDX report_data bound to the nonce:
// SHA-512(nonce), as recommended by VoltageGPU.
func reportDataFor(nonce []byte) [64]byte {
	return sha512.Sum512(nonce)
}

func (r *runner) attestTDX(ctx context.Context) {
	rep := r.report

	if _, err := os.Stat(r.cfg.TDXDevice); err != nil {
		rep.fail(sectionTDX, "TDX guest device", "%s not present — this is not an Intel TDX trust domain (%v)", r.cfg.TDXDevice, err)
		return
	}
	rep.pass(sectionTDX, "TDX guest device", "%s present", r.cfg.TDXDevice)

	reportData := reportDataFor(r.nonce)
	raw, err := r.quotes.Quote(ctx, reportData)
	if err != nil {
		hint := ""
		if errors.Is(err, os.ErrPermission) {
			hint = " (configfs-tsm requires root: re-run with sudo)"
		}
		rep.fail(sectionTDX, "Generate TD quote", "%v%s", err, hint)
		return
	}
	r.evidence.TDXQuote = raw
	rep.pass(sectionTDX, "Generate TD quote", "%d-byte quote from configfs-tsm", len(raw))

	if !bytes.HasPrefix(raw, tdxQuoteHeaderPrefix) {
		rep.fail(sectionTDX, "Quote header", "header %x, want %x (v4, ECDSA-P256, TDX)", raw[:min(len(raw), 6)], tdxQuoteHeaderPrefix)
		return
	}
	rep.pass(sectionTDX, "Quote header", "v4 / ECDSA-P256 / TEE type TDX")

	parsed, err := abi.QuoteToProto(raw)
	if err != nil {
		rep.fail(sectionTDX, "Parse quote", "%v", err)
		return
	}
	quote, ok := parsed.(*pb.QuoteV4)
	if !ok {
		rep.fail(sectionTDX, "Parse quote", "unsupported quote type %T", parsed)
		return
	}
	body := quote.GetTdQuoteBody()

	// Freshness: report_data must equal SHA-512(nonce). Check both the
	// parsed field and the raw offset the docs specify.
	if !bytes.Equal(body.GetReportData(), reportData[:]) ||
		len(raw) < reportDataOffset+64 || !bytes.Equal(raw[reportDataOffset:reportDataOffset+64], reportData[:]) {
		rep.fail(sectionTDX, "Nonce binding (report_data)", "report_data does not equal SHA-512(nonce) — quote is stale or replayed")
	} else {
		rep.pass(sectionTDX, "Nonce binding (report_data)", "report_data == SHA-512(nonce)")
	}

	attrs := body.GetTdAttributes()
	if len(attrs) == 0 || attrs[0]&tdAttrDebugBit != 0 {
		rep.fail(sectionTDX, "TD debug mode off", "TD_ATTRIBUTES=%x has DEBUG set — host can read TD memory", attrs)
	} else {
		rep.pass(sectionTDX, "TD debug mode off", "TD_ATTRIBUTES=%x", attrs)
	}

	intelRoot, err := IntelSGXRoot()
	if err != nil {
		rep.fail(sectionTDX, "Quote signature & Intel CA chain", "%v", err)
		return
	}
	roots := x509.NewCertPool()
	roots.AddCert(intelRoot)
	opts := &verify.Options{
		GetCollateral:    true,
		CheckRevocations: true,
		Getter:           pcsGetter{ctx: ctx, client: r.httpClient},
		Now:              time.Now(),
		TrustedRoots:     roots,
	}
	if err := verify.TdxQuote(quote, opts); err != nil {
		rep.fail(sectionTDX, "Quote signature & Intel CA chain", "%v", err)
	} else {
		rep.pass(sectionTDX, "Quote signature & Intel CA chain",
			"QE + PCK chain verified to pinned Intel SGX Root CA; CRLs checked; TCB UpToDate (Intel PCS)")
	}

	rtmrs := make([]string, 0, len(body.GetRtmrs()))
	for _, m := range body.GetRtmrs() {
		rtmrs = append(rtmrs, hex.EncodeToString(m))
	}
	rep.TDX = Measurements{
		MRTD:      hex.EncodeToString(body.GetMrTd()),
		RTMRs:     rtmrs,
		MRSeam:    hex.EncodeToString(body.GetMrSeam()),
		TDAttrs:   hex.EncodeToString(attrs),
		XFAM:      hex.EncodeToString(body.GetXfam()),
		TeeTCBSVN: hex.EncodeToString(body.GetTeeTcbSvn()),
	}
	rep.info(sectionTDX, "MRTD", "%s", rep.TDX.MRTD)
}
