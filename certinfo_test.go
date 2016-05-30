package certinfo

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"
)

// Compares a PEM-encoded certificate to a refernce file.
func testPair(t *testing.T, certFile, refFile string) {
	// Read and parse the certificate
	pemData, err := ioutil.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode([]byte(pemData))
	if block == nil || len(rest) > 0 {
		t.Fatal("Certificate decoding error")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	result, err := CertificateText(cert)
	if err != nil {
		t.Fatal(err)
	}
	resultData := []byte(result)

	// Read the reference output
	refData, err := ioutil.ReadFile(refFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resultData, refData) {
		t.Logf("Certificate '%s' did not match reference '%s'\n", certFile, refFile)
		t.Errorf("Certificate dump follows:\n%s\n", result)
	}
}

// Test the root CA certificate
func TestCertInfoRoot(t *testing.T) {
	testPair(t, "test_certs/root1.cert.pem", "test_certs/root1.cert.text")
}

// Test the leaf (user) RSA certificate
func TestCertInfoLeaf1(t *testing.T) {
	testPair(t, "test_certs/leaf1.cert.pem", "test_certs/leaf1.cert.text")
}

// Test the leaf (user) DSA certificate
func TestCertInfoLeaf2(t *testing.T) {
	testPair(t, "test_certs/leaf2.cert.pem", "test_certs/leaf2.cert.text")
}

// Test the leaf (user) ECDSA certificate
func TestCertInfoLeaf3(t *testing.T) {
	testPair(t, "test_certs/leaf3.cert.pem", "test_certs/leaf3.cert.text")
}
