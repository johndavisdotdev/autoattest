package attest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const sectionNRAS = "NVIDIA Remote Attestation Service (NRAS)"

type nrasEvidence struct {
	Evidence    string `json:"evidence"`
	Certificate string `json:"certificate"`
}

type nrasRequest struct {
	Nonce         string         `json:"nonce"`
	Arch          string         `json:"arch"`
	EvidenceList  []nrasEvidence `json:"evidence_list"`
	ClaimsVersion string         `json:"claims_version"`
}

// nrasToken is the decoded NRAS response: an overall EAT token plus one
// detached token per submodule (e.g. "GPU-0").
type nrasToken struct {
	Overall  string
	Detached map[string]string
}

// parseNRASResponse decodes [["JWT", "<overall>"], {"GPU-0": "<jwt>", ...}].
func parseNRASResponse(body []byte) (nrasToken, error) {
	var raw []json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nrasToken{}, fmt.Errorf("decoding NRAS response: %w", err)
	}
	if len(raw) < 2 {
		return nrasToken{}, fmt.Errorf("NRAS response has %d elements, want 2", len(raw))
	}
	var overall []string
	if err := json.Unmarshal(raw[0], &overall); err != nil || len(overall) != 2 || overall[0] != "JWT" {
		return nrasToken{}, errors.New("NRAS response: malformed overall token entry")
	}
	var detached map[string]string
	if err := json.Unmarshal(raw[1], &detached); err != nil {
		return nrasToken{}, fmt.Errorf("NRAS response: malformed detached tokens: %w", err)
	}
	return nrasToken{Overall: overall[1], Detached: detached}, nil
}

type jwks struct {
	Keys []struct {
		Kid string   `json:"kid"`
		X5C []string `json:"x5c"`
	} `json:"keys"`
}

// nrasEndpoints derives the JWKS URL and expected token issuer from the
// verifier URL, e.g. https://nras.attestation.nvidia.com.
func nrasEndpoints(verifierURL string) (jwksURL, issuer string, err error) {
	u, err := url.Parse(verifierURL)
	if err != nil {
		return "", "", err
	}
	if u.Scheme != "https" {
		return "", "", fmt.Errorf("NRAS URL must be https, got %q", u.Scheme)
	}
	issuer = u.Scheme + "://" + u.Host
	return issuer + "/.well-known/jwks.json", issuer, nil
}

// nrasVerifier verifies NRAS-signed EAT tokens.
type nrasVerifier struct {
	keys   map[string]*x509.Certificate // kid → signing cert
	issuer string                       // expected "iss" claim
	now    func() time.Time
}

func (r *runner) fetchJWKS(ctx context.Context, jwksURL, issuer string) (*nrasVerifier, error) {
	body, err := r.httpGet(ctx, jwksURL)
	if err != nil {
		return nil, err
	}
	var set jwks
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("decoding JWKS: %w", err)
	}
	v := &nrasVerifier{keys: map[string]*x509.Certificate{}, issuer: issuer, now: time.Now}
	for _, k := range set.Keys {
		cert, err := verifyX5C(k.X5C, time.Now())
		if err != nil {
			continue // skip unusable keys; a token referencing one will fail
		}
		v.keys[k.Kid] = cert
	}
	if len(v.keys) == 0 {
		return nil, errors.New("JWKS contains no usable NVIDIA signing keys")
	}
	return v, nil
}

// verifyX5C checks the JWKS x5c chain is internally consistent (each cert
// signed by the next, within validity, CA flags correct) and is issued under
// the NVIDIA Attestation Service CA. The JWKS itself is authenticated by TLS
// to NVIDIA's host, which is the same trust model as NVIDIA's own SDK.
func verifyX5C(x5c []string, now time.Time) (*x509.Certificate, error) {
	if len(x5c) == 0 {
		return nil, errors.New("empty x5c")
	}
	certs := make([]*x509.Certificate, 0, len(x5c))
	for _, s := range x5c {
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			return nil, fmt.Errorf("x5c cert %q not valid at %s", c.Subject.CommonName, now)
		}
		certs = append(certs, c)
	}
	for i := 0; i+1 < len(certs); i++ {
		if !certs[i+1].IsCA {
			return nil, fmt.Errorf("x5c issuer %q is not a CA", certs[i+1].Subject.CommonName)
		}
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return nil, fmt.Errorf("x5c chain broken at %q: %w", certs[i].Subject.CommonName, err)
		}
	}
	top := certs[len(certs)-1]
	if !strings.HasPrefix(top.Issuer.CommonName, "NVIDIA Attestation Service") ||
		!slices.Contains(top.Issuer.Organization, "NVIDIA Corporation") {
		return nil, fmt.Errorf("x5c chain issued by %q, not the NVIDIA Attestation Service CA", top.Issuer.String())
	}
	return certs[0], nil
}

func (v *nrasVerifier) parse(token string) (jwt.MapClaims, *x509.Certificate, error) {
	var signer *x509.Certificate
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		cert, ok := v.keys[kid]
		if !ok {
			return nil, fmt.Errorf("unknown signing key id %q", kid)
		}
		signer = cert
		return cert.PublicKey, nil
	},
		jwt.WithValidMethods([]string{"ES384"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(v.issuer),
		jwt.WithLeeway(30*time.Second),
		jwt.WithTimeFunc(v.now),
	)
	if err != nil {
		return nil, nil, err
	}
	return claims, signer, nil
}

// submodDigest extracts the digest the overall token commits to for a
// detached submodule token: "submods": {"GPU-0": ["DIGEST", ["SHA256", "<hex>"]]}.
func submodDigest(overall jwt.MapClaims, name string) (alg, digest string, ok bool) {
	submods, _ := overall["submods"].(map[string]any)
	entry, _ := submods[name].([]any)
	if len(entry) != 2 || entry[0] != "DIGEST" {
		return "", "", false
	}
	pair, _ := entry[1].([]any)
	if len(pair) != 2 {
		return "", "", false
	}
	alg, _ = pair[0].(string)
	digest, _ = pair[1].(string)
	return alg, digest, alg != "" && digest != ""
}

func digestMatches(alg, want, token string) bool {
	var h hash.Hash
	switch strings.ToUpper(strings.ReplaceAll(alg, "-", "")) {
	case "SHA256":
		h = sha256.New()
	case "SHA384":
		h = sha512.New384()
	case "SHA512":
		h = sha512.New()
	default:
		return false
	}
	h.Write([]byte(token))
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), want)
}

func claimBool(c jwt.MapClaims, key string) (bool, bool) {
	v, ok := c[key].(bool)
	return v, ok
}

// requiredGPUClaims must all be present and true in every GPU token. A token
// that simply omits a check must not pass, so presence is enforced here and
// failedClaims additionally catches any other x-nvidia-* claim that is false.
var requiredGPUClaims = []string{
	"x-nvidia-gpu-arch-check",
	"x-nvidia-gpu-attestation-report-parsed",
	"x-nvidia-gpu-attestation-report-nonce-match",
	"x-nvidia-gpu-attestation-report-signature-verified",
	"x-nvidia-gpu-attestation-report-cert-chain-validated",
	"x-nvidia-gpu-driver-rim-fetched",
	"x-nvidia-gpu-driver-rim-schema-validated",
	"x-nvidia-gpu-driver-rim-signature-verified",
	"x-nvidia-gpu-driver-rim-cert-validated",
	"x-nvidia-gpu-driver-rim-measurements-available",
	"x-nvidia-gpu-vbios-rim-fetched",
	"x-nvidia-gpu-vbios-rim-schema-validated",
	"x-nvidia-gpu-vbios-rim-signature-verified",
	"x-nvidia-gpu-vbios-rim-cert-validated",
	"x-nvidia-gpu-vbios-rim-measurements-available",
	"x-nvidia-gpu-vbios-index-no-conflict",
}

func missingClaims(c jwt.MapClaims) []string {
	var out []string
	for _, k := range requiredGPUClaims {
		if _, ok := c[k].(bool); !ok {
			out = append(out, k+"(missing)")
		}
	}
	return out
}

// failedClaims walks a claim set and reports every x-nvidia-* boolean that is
// false, and every certificate status / OCSP status that isn't healthy.
func failedClaims(prefix string, m map[string]any) []string {
	var bad []string
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		switch val := m[k].(type) {
		case bool:
			if strings.HasPrefix(k, "x-nvidia-") && !val {
				bad = append(bad, path)
			}
		case string:
			switch k {
			case "x-nvidia-cert-status":
				if val != "valid" {
					bad = append(bad, path+"="+val)
				}
			case "x-nvidia-cert-ocsp-status":
				if val != "good" {
					bad = append(bad, path+"="+val)
				}
			}
		case map[string]any:
			bad = append(bad, failedClaims(path, val)...)
		}
	}
	return bad
}

func (r *runner) httpGet(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d: %s", u, resp.StatusCode, truncate(body, 200))
	}
	return body, nil
}

func truncate(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func (r *runner) callNRAS(ctx context.Context, evs []GPUEvidence) ([]byte, error) {
	arch := evs[0].Info.Arch
	reqBody := nrasRequest{
		Nonce:         hex.EncodeToString(r.nonce),
		Arch:          arch,
		ClaimsVersion: r.cfg.ClaimsVersion,
	}
	for _, ev := range evs {
		if ev.Info.Arch != arch {
			return nil, fmt.Errorf("mixed GPU architectures (%s, %s) cannot be attested in one NRAS request", arch, ev.Info.Arch)
		}
		reqBody.EvidenceList = append(reqBody.EvidenceList, nrasEvidence{
			Evidence:    base64.StdEncoding.EncodeToString(ev.Report),
			Certificate: base64.StdEncoding.EncodeToString(ev.CertChainPEM),
		})
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.NRASURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if r.cfg.NRASServiceKey != "" {
		req.Header.Set("Authorization", "nv-sak "+r.cfg.NRASServiceKey)
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(body, 300))
	}
	return body, nil
}

// attestNRAS submits GPU evidence to NRAS and verifies the signed result.
func (r *runner) attestNRAS(ctx context.Context, evs []GPUEvidence) {
	rep := r.report
	if len(evs) == 0 {
		rep.fail(sectionNRAS, "Remote GPU attestation", "skipped: no GPU evidence collected")
		return
	}

	jwksURL, issuer, err := nrasEndpoints(r.cfg.NRASURL)
	if err != nil {
		rep.fail(sectionNRAS, "NRAS endpoint", "%v", err)
		return
	}

	body, err := r.callNRAS(ctx, evs)
	if err != nil {
		rep.fail(sectionNRAS, "Submit evidence", "%s: %v", r.cfg.NRASURL, err)
		return
	}
	r.evidence.NRASResponse = body
	rep.pass(sectionNRAS, "Submit evidence", "%d GPU(s) to %s", len(evs), r.cfg.NRASURL)

	tok, err := parseNRASResponse(body)
	if err != nil {
		rep.fail(sectionNRAS, "Token signature", "%v", err)
		return
	}

	verifier, err := r.fetchJWKS(ctx, jwksURL, issuer)
	if err != nil {
		rep.fail(sectionNRAS, "Token signature", "JWKS %s: %v", jwksURL, err)
		return
	}

	overall, signer, err := verifier.parse(tok.Overall)
	if err != nil {
		rep.fail(sectionNRAS, "Token signature", "overall EAT token: %v", err)
		return
	}
	rep.pass(sectionNRAS, "Token signature", "ES384 by %q (issuer %q)", signer.Subject.CommonName, signer.Issuer.CommonName)

	nonceHex := hex.EncodeToString(r.nonce)
	if n, _ := overall["eat_nonce"].(string); !strings.EqualFold(n, nonceHex) {
		rep.fail(sectionNRAS, "Token nonce", "eat_nonce %q != our nonce", n)
	} else {
		rep.pass(sectionNRAS, "Token nonce", "eat_nonce matches")
	}

	if ok, present := claimBool(overall, "x-nvidia-overall-att-result"); ok {
		rep.pass(sectionNRAS, "Overall attestation result", "x-nvidia-overall-att-result=true")
	} else {
		rep.fail(sectionNRAS, "Overall attestation result", "x-nvidia-overall-att-result=%v (present=%v)", ok, present)
	}

	names := make([]string, 0, len(tok.Detached))
	for name := range tok.Detached {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) != len(evs) {
		rep.fail(sectionNRAS, "GPU claims", "NRAS returned %d GPU token(s) for %d GPU(s)", len(names), len(evs))
	}

	for _, name := range names {
		raw := tok.Detached[name]
		label := name
		if alg, want, ok := submodDigest(overall, name); !ok || !digestMatches(alg, want, raw) {
			rep.fail(sectionNRAS, label+" token binding", "detached token is not committed to by the overall token's submods digest")
			continue
		}
		claims, _, err := verifier.parse(raw)
		if err != nil {
			rep.fail(sectionNRAS, label+" token signature", "%v", err)
			continue
		}
		if n, _ := claims["eat_nonce"].(string); n != "" && !strings.EqualFold(n, nonceHex) {
			rep.fail(sectionNRAS, label+" nonce", "eat_nonce %q != our nonce", n)
		}
		if m, _ := claims["measres"].(string); m == "success" {
			rep.pass(sectionNRAS, label+" measurements (measres)", "firmware/driver measurements match NVIDIA golden RIMs")
		} else {
			rep.fail(sectionNRAS, label+" measurements (measres)", "measres=%q", m)
		}
		if ok, _ := claimBool(claims, "x-nvidia-gpu-attestation-report-nonce-match"); ok {
			rep.pass(sectionNRAS, label+" report nonce match", "")
		} else {
			rep.fail(sectionNRAS, label+" report nonce match", "x-nvidia-gpu-attestation-report-nonce-match is not true")
		}
		if ok, _ := claimBool(claims, "secboot"); ok {
			rep.pass(sectionNRAS, label+" secure boot", "secboot=true")
		} else {
			rep.fail(sectionNRAS, label+" secure boot", "secboot is not true")
		}
		if d, _ := claims["dbgstat"].(string); d == "disabled" {
			rep.pass(sectionNRAS, label+" debug status", "dbgstat=disabled")
		} else {
			rep.fail(sectionNRAS, label+" debug status", "dbgstat=%q, want disabled", d)
		}
		bad := missingClaims(claims)
		bad = append(bad, failedClaims("", claims)...)
		if len(bad) > 0 {
			rep.fail(sectionNRAS, label+" verifier claims", "failing or missing: %s", strings.Join(bad, ", "))
		} else {
			rep.pass(sectionNRAS, label+" verifier claims",
				"%d required checks true (report cert chain, report signature, driver+VBIOS RIM certs/signatures)", len(requiredGPUClaims))
		}
		if hw, _ := claims["hwmodel"].(string); hw != "" {
			rep.info(sectionNRAS, label+" hwmodel", "%s", hw)
		}
		if w, ok := claims["x-nvidia-attestation-warning"]; ok && w != nil && w != "" {
			rep.warn(sectionNRAS, label+" warning", "%v", w)
		}
	}
}
