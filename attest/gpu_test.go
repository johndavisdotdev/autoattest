package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"testing"
)

// buildSPDMReport makes a synthetic GET_MEASUREMENTS request+response signed
// with key, in the layout NVIDIA GPUs emit.
func buildSPDMReport(t *testing.T, nonce [32]byte, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	req := make([]byte, spdmRequestLen)
	req[0], req[1] = 0x11, 0xE0
	copy(req[spdmNonceOffset:], nonce[:])

	record := []byte("measurement-record-bytes")
	opaque := []byte("opaque-data")
	resp := []byte{0x11, 0x60, 0, 0, 1, byte(len(record)), 0, 0}
	resp = append(resp, record...)
	resp = append(resp, make([]byte, 32)...) // responder nonce
	resp = binary.LittleEndian.AppendUint16(resp, uint16(len(opaque)))
	resp = append(resp, opaque...)

	signed := append(req, resp...)
	digest := sha512.Sum384(signed)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 96)
	r.FillBytes(sig[:48])
	s.FillBytes(sig[48:])
	return append(signed, sig...)
}

type fakeGPUs struct {
	state CCState
	evs   []GPUEvidence
	err   error
}

func (f fakeGPUs) CCState() (CCState, error)                  { return f.state, nil }
func (f fakeGPUs) Evidence(n [32]byte) ([]GPUEvidence, error) { return f.evs, f.err }
func (f fakeGPUs) Close() error                               { return nil }

var goodCC = CCState{CCFeatureEnabled: true, Production: true, GPUsReady: true, CPUCaps: "INTEL TDX", GPUsCCCapable: true, MultiGPUMode: "None"}

func TestSPDMSignature(t *testing.T) {
	leaf := newCert(t, pkix.Name{CommonName: "gpu"}, nil, false, elliptic.P384())
	var nonce [32]byte
	nonce[0] = 7
	raw := buildSPDMReport(t, nonce, leaf.key)

	rep, err := parseSPDMReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	if rep.RequestNonce[0] != 7 {
		t.Fatal("nonce not parsed from request")
	}
	if err := verifySPDMSignature(rep, leaf.cert); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	tampered := append([]byte(nil), raw...)
	tampered[spdmRequestLen+10] ^= 0xFF // flip a measurement byte
	trep, err := parseSPDMReport(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySPDMSignature(trep, leaf.cert); err == nil {
		t.Fatal("tampered report accepted")
	}

	other := newCert(t, pkix.Name{CommonName: "other"}, nil, false, elliptic.P384())
	if err := verifySPDMSignature(rep, other.cert); err == nil {
		t.Fatal("report accepted with wrong device key")
	}

	if _, err := parseSPDMReport(raw[:len(raw)-10]); err == nil {
		t.Fatal("truncated report accepted")
	}
}

func TestGPUChecks(t *testing.T) {
	// A self-made chain: valid signatures, but not rooted in the pinned
	// NVIDIA Device Identity CA — must be rejected.
	fakeRoot := newCert(t, pkix.Name{CommonName: "NVIDIA Device Identity CA"}, nil, true, elliptic.P384())
	leaf := newCert(t, pkix.Name{CommonName: "GH100 device"}, fakeRoot, false, elliptic.P384())
	chainPEM := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.cert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fakeRoot.cert.Raw})...)

	nonce := make([]byte, 32)
	nonce[31] = 9
	var n32 [32]byte
	copy(n32[:], nonce)

	tests := []struct {
		name  string
		gpus  fakeGPUs
		check string
		want  Status
	}{
		{"cc off", fakeGPUs{state: CCState{Production: true, CPUCaps: "INTEL TDX"}}, "CC State ON", StatusFail},
		{"devtools on", fakeGPUs{state: func() CCState { s := goodCC; s.DevToolsMode = true; return s }()}, "DevTools mode OFF", StatusFail},
		{"not tdx", fakeGPUs{state: func() CCState { s := goodCC; s.CPUCaps = "None"; return s }()}, "CPU CC capability", StatusFail},
		{"no gpus", fakeGPUs{state: goodCC}, "Collect GPU evidence", StatusFail},
		{"nvml error", fakeGPUs{state: goodCC, err: errors.New("boom")}, "Collect GPU evidence", StatusFail},
		{"untrusted root", fakeGPUs{state: goodCC, evs: []GPUEvidence{{
			Info: GPUInfo{Arch: "HOPPER"}, Report: buildSPDMReport(t, n32, leaf.key), CertChainPEM: chainPEM,
		}}}, "GPU 0 certificate chain", StatusFail},
		{"signature ok on own key", fakeGPUs{state: goodCC, evs: []GPUEvidence{{
			Info: GPUInfo{Arch: "HOPPER"}, Report: buildSPDMReport(t, n32, leaf.key), CertChainPEM: chainPEM,
		}}}, "GPU 0 report signature", StatusPass},
		{"stale nonce", fakeGPUs{state: goodCC, evs: []GPUEvidence{{
			Info: GPUInfo{Arch: "HOPPER"}, Report: buildSPDMReport(t, [32]byte{}, leaf.key), CertChainPEM: chainPEM,
		}}}, "GPU 0 nonce binding", StatusFail},
		{"unsupported arch", fakeGPUs{state: goodCC, evs: []GPUEvidence{{
			Info: GPUInfo{Arch: "UNSUPPORTED(8)"},
		}}}, "GPU 0 architecture", StatusFail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &runner{cfg: withDefaults(Config{}), report: newReport(), nonce: nonce, gpus: tt.gpus}
			r.attestGPUs()
			requireStatus(t, r.report, tt.check, tt.want)
		})
	}
}

func TestPinnedRoots(t *testing.T) {
	if c, err := IntelSGXRoot(); err != nil || c.Subject.CommonName != "Intel SGX Root CA" {
		t.Fatalf("Intel root: %v %v", c, err)
	}
	if c, err := NVIDIADeviceRoot(); err != nil || c.Subject.CommonName != "NVIDIA Device Identity CA" {
		t.Fatalf("NVIDIA root: %v %v", c, err)
	}
	if _, err := loadPinnedRoot("x", intelSGXRootPEM, nvidiaDeviceRootSHA256); err == nil {
		t.Fatal("fingerprint mismatch not detected")
	}
}
