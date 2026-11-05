package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const (
	sectionGPU = "NVIDIA GPU (Confidential Compute)"

	spdmRequestLen   = 37 // SPDM GET_MEASUREMENTS request
	spdmNonceOffset  = 4  // requester nonce inside the request
	p384SignatureLen = 96 // raw r||s
)

// spdmReport is the minimal parse of an NVIDIA GPU attestation report needed
// to verify it locally.
type spdmReport struct {
	RequestNonce []byte
	Signed       []byte // bytes covered by the signature
	Signature    []byte
}

// parseSPDMReport splits a GET_MEASUREMENTS request+response into the signed
// portion and signature. Layout (DMTF SPDM 1.1, response offsets):
//
//	0 ver | 1 code | 2 p1 | 3 p2 | 4 nblocks | 5..8 L1 (LE24) | 8 record[L1]
//	| nonce[32] | L2 (LE16) | opaque[L2] | signature[96]
func parseSPDMReport(raw []byte) (spdmReport, error) {
	if len(raw) < spdmRequestLen+8 {
		return spdmReport{}, errors.New("report too short")
	}
	resp := raw[spdmRequestLen:]
	l1 := int(resp[5]) | int(resp[6])<<8 | int(resp[7])<<16
	opaqueLenAt := 8 + l1 + 32
	if len(resp) < opaqueLenAt+2 {
		return spdmReport{}, errors.New("report truncated before opaque data")
	}
	l2 := int(binary.LittleEndian.Uint16(resp[opaqueLenAt:]))
	sigAt := spdmRequestLen + opaqueLenAt + 2 + l2
	if len(raw) < sigAt+p384SignatureLen {
		return spdmReport{}, fmt.Errorf("report truncated: need %d bytes, have %d", sigAt+p384SignatureLen, len(raw))
	}
	return spdmReport{
		RequestNonce: raw[spdmNonceOffset : spdmNonceOffset+32],
		Signed:       raw[:sigAt],
		Signature:    raw[sigAt : sigAt+p384SignatureLen],
	}, nil
}

func parsePEMChain(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificates in chain")
	}
	return certs, nil
}

// verifyGPUCertChain checks that the leaf chains to the pinned NVIDIA Device
// Identity CA. The device-supplied root (if any) is never trusted: only the
// compiled-in root is used as an anchor.
func verifyGPUCertChain(chain []*x509.Certificate, root *x509.Certificate, now time.Time) error {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	leaf := chain[0]
	// NVIDIA device certificates carry NVIDIA-specific critical extensions
	// (e.g. FWID) that Go doesn't know about. Signatures, validity and CA
	// constraints are still enforced by x509.Verify; NRAS validates FWIDs.
	for _, c := range chain {
		c.UnhandledCriticalExtensions = nil
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

func verifySPDMSignature(rep spdmReport, leaf *x509.Certificate) error {
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P384() {
		return fmt.Errorf("leaf key is %T, want ECDSA P-384", leaf.PublicKey)
	}
	digest := sha512.Sum384(rep.Signed)
	r := new(big.Int).SetBytes(rep.Signature[:48])
	s := new(big.Int).SetBytes(rep.Signature[48:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return errors.New("ECDSA-P384 signature does not verify against the GPU leaf certificate")
	}
	return nil
}

// attestGPUs checks CC mode and collects + locally verifies GPU evidence.
// It returns the evidence for remote verification by NRAS.
func (r *runner) attestGPUs() []GPUEvidence {
	rep := r.report

	st, err := r.gpus.CCState()
	if err != nil {
		rep.fail(sectionGPU, "Read CC state", "%v", err)
		return nil
	}
	if st.CCFeatureEnabled {
		rep.pass(sectionGPU, "CC State ON", "confidential compute enabled")
	} else {
		rep.fail(sectionGPU, "CC State ON", "confidential compute is OFF — GPU memory and PCIe traffic are not protected")
	}
	if st.DevToolsMode {
		rep.fail(sectionGPU, "DevTools mode OFF", "DevTools mode is ON — debuggers can inspect GPU state")
	} else {
		rep.pass(sectionGPU, "DevTools mode OFF", "")
	}
	if st.Production {
		rep.pass(sectionGPU, "Production environment", "")
	} else {
		rep.fail(sectionGPU, "Production environment", "CC environment is not PROD (simulated)")
	}
	if st.GPUsReady {
		rep.pass(sectionGPU, "GPUs ready state", "accepting work")
	} else {
		rep.warn(sectionGPU, "GPUs ready state", "not ready — CC GPUs not yet released for work")
	}
	if st.CPUCaps == "INTEL TDX" {
		rep.pass(sectionGPU, "CPU CC capability", "%s", st.CPUCaps)
	} else {
		rep.fail(sectionGPU, "CPU CC capability", "driver reports CPU CC capability %q, want INTEL TDX", st.CPUCaps)
	}
	rep.info(sectionGPU, "Multi-GPU mode", "%s", st.MultiGPUMode)

	evs, err := r.gpus.Evidence(r.gpuNonce())
	if err != nil {
		rep.fail(sectionGPU, "Collect GPU evidence", "%v", err)
		return nil
	}
	if len(evs) == 0 {
		rep.fail(sectionGPU, "Collect GPU evidence", "no GPUs found")
		return nil
	}

	root, err := NVIDIADeviceRoot()
	if err != nil {
		rep.fail(sectionGPU, "NVIDIA Device Identity CA", "%v", err)
		return nil
	}

	for _, ev := range evs {
		rep.GPUs = append(rep.GPUs, ev.Info)
		r.verifyGPUEvidence(ev, root)
	}
	return evs
}

func (r *runner) verifyGPUEvidence(ev GPUEvidence, root *x509.Certificate) {
	rep := r.report
	label := fmt.Sprintf("GPU %d", ev.Info.Index)
	rep.info(sectionGPU, label, "%s %s (%s)", ev.Info.Name, ev.Info.UUID, ev.Info.Arch)

	if strings.HasPrefix(ev.Info.Arch, "UNSUPPORTED") {
		rep.fail(sectionGPU, label+" architecture", "%s is not CC-attestable (need Hopper or Blackwell)", ev.Info.Arch)
		return
	}

	chain, err := parsePEMChain(ev.CertChainPEM)
	if err != nil {
		rep.fail(sectionGPU, label+" certificate chain", "%v", err)
		return
	}
	if err := verifyGPUCertChain(chain, root, time.Now()); err != nil {
		rep.fail(sectionGPU, label+" certificate chain", "does not chain to pinned NVIDIA Device Identity CA: %v", err)
	} else {
		rep.pass(sectionGPU, label+" certificate chain", "%d certs → pinned NVIDIA Device Identity CA", len(chain))
	}

	spdm, err := parseSPDMReport(ev.Report)
	if err != nil {
		rep.fail(sectionGPU, label+" report signature", "parse: %v", err)
		return
	}
	nonce := r.gpuNonce()
	if !bytes.Equal(spdm.RequestNonce, nonce[:]) {
		rep.fail(sectionGPU, label+" nonce binding", "report nonce %x != our nonce", spdm.RequestNonce)
	} else {
		rep.pass(sectionGPU, label+" nonce binding", "report carries our nonce")
	}
	if err := verifySPDMSignature(spdm, chain[0]); err != nil {
		rep.fail(sectionGPU, label+" report signature", "%v", err)
	} else {
		rep.pass(sectionGPU, label+" report signature", "signed by GPU device key (ECDSA P-384)")
	}
}
