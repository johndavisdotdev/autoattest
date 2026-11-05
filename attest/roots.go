package attest

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

// Trust anchors are compiled in and pinned by SHA-256 fingerprint so that a
// tampered binary or file swap is caught at startup rather than silently
// trusted.

//go:embed certs/intel_sgx_root_ca.pem
var intelSGXRootPEM []byte

//go:embed certs/nvidia_device_identity_ca.pem
var nvidiaDeviceRootPEM []byte

const (
	// Intel SGX Root CA — https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem
	intelSGXRootSHA256 = "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3"
	// NVIDIA Device Identity CA — nvtrust local_gpu_verifier certs/verifier_device_root.pem
	nvidiaDeviceRootSHA256 = "102bf659d5419614c9d8e6aecebc80454eb26b1df6a769ac720b9a690b167b48"
)

func loadPinnedRoot(name string, pemBytes []byte, wantHex string) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%s: embedded PEM is invalid", name)
	}
	sum := sha256.Sum256(block.Bytes)
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		return nil, fmt.Errorf("%s: bad pinned fingerprint: %w", name, err)
	}
	if !bytes.Equal(sum[:], want) {
		return nil, fmt.Errorf("%s: embedded root fingerprint %x does not match pin", name, sum)
	}
	return x509.ParseCertificate(block.Bytes)
}

// IntelSGXRoot returns the pinned Intel SGX Root CA.
func IntelSGXRoot() (*x509.Certificate, error) {
	return loadPinnedRoot("Intel SGX Root CA", intelSGXRootPEM, intelSGXRootSHA256)
}

// NVIDIADeviceRoot returns the pinned NVIDIA Device Identity CA.
func NVIDIADeviceRoot() (*x509.Certificate, error) {
	return loadPinnedRoot("NVIDIA Device Identity CA", nvidiaDeviceRootPEM, nvidiaDeviceRootSHA256)
}
