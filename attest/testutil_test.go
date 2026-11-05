package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serial int64

func newCert(t *testing.T, subject pkix.Name, parent *testCA, isCA bool, curve elliptic.Curve) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial++
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	parentCert, parentKey := tmpl, key
	if parent != nil {
		parentCert, parentKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: c, key: key}
}

func newReport() *Report { return &Report{Started: time.Now()} }

func findCheck(r *Report, name string) (Check, bool) {
	for _, c := range r.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return Check{}, false
}

func requireStatus(t *testing.T, r *Report, name string, want Status) {
	t.Helper()
	c, ok := findCheck(r, name)
	if !ok {
		t.Fatalf("check %q not found; checks: %+v", name, r.Checks)
	}
	if c.Status != want {
		t.Fatalf("check %q = %s (%s), want %s", name, c.Status, c.Detail, want)
	}
}
