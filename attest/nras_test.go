package attest

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeNRAS is an httptest TLS server mimicking NRAS + its JWKS endpoint.
type fakeNRAS struct {
	srv    *httptest.Server
	signer *testCA
	inter  *testCA
	kid    string
	// mutate lets a test alter claims or the encoded response.
	overall  func(jwt.MapClaims)
	detached func(jwt.MapClaims)
	tamper   func(overall string, detached map[string]string) (string, map[string]string)
	gotReq   nrasRequest
}

func newFakeNRAS(t *testing.T, rootName string) *fakeNRAS {
	t.Helper()
	root := newCert(t, pkix.Name{CommonName: rootName, Organization: []string{"NVIDIA Corporation"}}, nil, true, elliptic.P384())
	inter := newCert(t, pkix.Name{CommonName: "NVIDIA Attestation Service GPU Intermediate 999", Organization: []string{"NVIDIA Corporation"}}, root, true, elliptic.P384())
	leaf := newCert(t, pkix.Name{CommonName: "NVIDIA Attestation Service GPU GH100", Organization: []string{"NVIDIA Corporation"}}, inter, false, elliptic.P384())
	f := &fakeNRAS{signer: leaf, inter: inter, kid: "test-kid"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kid": f.kid,
			"kty": "EC",
			"x5c": []string{
				base64.StdEncoding.EncodeToString(f.signer.cert.Raw),
				base64.StdEncoding.EncodeToString(f.inter.cert.Raw),
			},
		}}})
	})
	mux.HandleFunc("/v3/attest/gpu", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&f.gotReq); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		iss := "https://" + r.Host
		now := time.Now()
		gpu := jwt.MapClaims{
			"iss": iss, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"eat_nonce": f.gotReq.Nonce, "measres": "success", "secboot": true, "dbgstat": "disabled",
			"hwmodel": "GH100",
		}
		for _, k := range requiredGPUClaims {
			gpu[k] = true
		}
		if f.detached != nil {
			f.detached(gpu)
		}
		gpuTok := f.sign(t, gpu)
		sum := sha256.Sum256([]byte(gpuTok))
		overall := jwt.MapClaims{
			"iss": iss, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"eat_nonce": f.gotReq.Nonce, "x-nvidia-overall-att-result": true,
			"submods": map[string]any{"GPU-0": []any{"DIGEST", []any{"SHA-256", hex.EncodeToString(sum[:])}}},
		}
		if f.overall != nil {
			f.overall(overall)
		}
		ot, dt := f.sign(t, overall), map[string]string{"GPU-0": gpuTok}
		if f.tamper != nil {
			ot, dt = f.tamper(ot, dt)
		}
		json.NewEncoder(w).Encode([]any{[]string{"JWT", ot}, dt})
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeNRAS) sign(t *testing.T, c jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES384, c)
	tok.Header["kid"] = f.kid
	s, err := tok.SignedString(f.signer.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func runNRAS(t *testing.T, f *fakeNRAS) *Report {
	t.Helper()
	nonce := make([]byte, 32)
	nonce[0] = 0xAB
	r := &runner{
		cfg:        withDefaults(Config{NRASURL: f.srv.URL + "/v3/attest/gpu"}),
		report:     newReport(),
		nonce:      nonce,
		httpClient: f.srv.Client(),
	}
	r.attestNRAS(t.Context(), []GPUEvidence{{
		Info:         GPUInfo{Arch: "HOPPER"},
		Report:       []byte("report"),
		CertChainPEM: []byte("chain"),
	}})
	r.report.finalize()
	return r.report
}

const nrasRoot = "NVIDIA Attestation Service CA 001"

func TestNRASHappyPath(t *testing.T) {
	f := newFakeNRAS(t, nrasRoot)
	rep := runNRAS(t, f)
	if !rep.Safe {
		t.Fatalf("expected safe, failures: %+v", rep.Failures())
	}
	if f.gotReq.Arch != "HOPPER" || f.gotReq.ClaimsVersion != DefaultClaimsVersion || len(f.gotReq.EvidenceList) != 1 {
		t.Fatalf("unexpected request: %+v", f.gotReq)
	}
	if got, _ := base64.StdEncoding.DecodeString(f.gotReq.EvidenceList[0].Evidence); string(got) != "report" {
		t.Fatalf("evidence not base64 of report: %q", got)
	}
}

func TestNRASRejects(t *testing.T) {
	tests := []struct {
		name     string
		root     string
		overall  func(jwt.MapClaims)
		detached func(jwt.MapClaims)
		tamper   func(string, map[string]string) (string, map[string]string)
		check    string
	}{
		{
			name:    "overall result false",
			overall: func(c jwt.MapClaims) { c["x-nvidia-overall-att-result"] = false },
			check:   "Overall attestation result",
		},
		{
			name:    "replayed nonce",
			overall: func(c jwt.MapClaims) { c["eat_nonce"] = hex.EncodeToString(make([]byte, 32)) },
			check:   "Token nonce",
		},
		{
			name:     "measurement mismatch",
			detached: func(c jwt.MapClaims) { c["measres"] = "fail" },
			check:    "GPU-0 measurements (measres)",
		},
		{
			name:     "cert chain not validated",
			detached: func(c jwt.MapClaims) { c["x-nvidia-gpu-attestation-report-cert-chain-validated"] = false },
			check:    "GPU-0 verifier claims",
		},
		{
			name:     "required claim omitted",
			detached: func(c jwt.MapClaims) { delete(c, "x-nvidia-gpu-driver-rim-signature-verified") },
			check:    "GPU-0 verifier claims",
		},
		{
			name:     "gpu debug enabled",
			detached: func(c jwt.MapClaims) { c["dbgstat"] = "enabled" },
			check:    "GPU-0 debug status",
		},
		{
			name:     "secure boot off",
			detached: func(c jwt.MapClaims) { c["secboot"] = false },
			check:    "GPU-0 secure boot",
		},
		{
			name:    "wrong issuer",
			overall: func(c jwt.MapClaims) { c["iss"] = "https://evil.example" },
			check:   "Token signature",
		},
		{
			name:    "expired token",
			overall: func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() },
			check:   "Token signature",
		},
		{
			name: "detached token swapped",
			tamper: func(o string, d map[string]string) (string, map[string]string) {
				d = maps.Clone(d)
				d["GPU-0"] = d["GPU-0"] + "x" // breaks digest binding
				return o, d
			},
			check: "GPU-0 token binding",
		},
		{
			name: "overall signature tampered",
			tamper: func(o string, d map[string]string) (string, map[string]string) {
				b := []byte(o)
				b[len(b)-5] ^= 0x01
				return string(b), d
			},
			check: "Token signature",
		},
		{
			name:  "signing chain not under NVIDIA Attestation Service CA",
			root:  "Evil Root CA",
			check: "Token signature",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := tt.root
			if root == "" {
				root = nrasRoot
			}
			f := newFakeNRAS(t, root)
			f.overall, f.detached, f.tamper = tt.overall, tt.detached, tt.tamper
			rep := runNRAS(t, f)
			if rep.Safe {
				t.Fatal("expected NOT safe")
			}
			requireStatus(t, rep, tt.check, StatusFail)
		})
	}
}

func TestNRASEndpointsRequireHTTPS(t *testing.T) {
	if _, _, err := nrasEndpoints("http://nras.attestation.nvidia.com/v3/attest/gpu"); err == nil {
		t.Fatal("expected error for http URL")
	}
	j, iss, err := nrasEndpoints(DefaultNRASURL)
	if err != nil || j != "https://nras.attestation.nvidia.com/.well-known/jwks.json" || iss != "https://nras.attestation.nvidia.com" {
		t.Fatalf("got %q %q %v", j, iss, err)
	}
}
