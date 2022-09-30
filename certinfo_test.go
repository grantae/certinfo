package certinfo

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type InputType int

const (
	tCertificate InputType = iota
	tCertificateRequest
)

// Compares a PEM-encoded certificate to a reference file.
func testPair(t *testing.T, certFile, refFile string, inputType InputType) {
	// Read and parse the certificate
	pemData, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(pemData)
	if block == nil || len(rest) > 0 {
		t.Fatal("Certificate decoding error")
	}
	var result string
	switch inputType {
	case tCertificate:
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		result, err = CertificateText(cert)
		if err != nil {
			t.Fatal(err)
		}
	case tCertificateRequest:
		cert, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		result, err = CertificateRequestText(cert)
		if err != nil {
			t.Fatal(err)
		}
	}
	resultData := []byte(result)

	// Read the reference output
	refData, err := os.ReadFile(refFile)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a diff and check if it's empty; if not, report error
	if diff := cmp.Diff(refData, resultData); diff != "" {
		t.Logf("'%s' did not match reference '%s'\n", certFile, refFile)
		t.Errorf("Diff follows:\n%s\n", diff)
	}
}

// Compares a PEM-encoded certificate to a reference file.
func testPairShort(t *testing.T, certFile, refFile string, inputType InputType) {
	// Read and parse the certificate
	pemData, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(pemData)
	if block == nil || len(rest) > 0 {
		t.Fatal("Certificate decoding error")
	}
	var result string
	switch inputType {
	case tCertificate:
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		result, err = CertificateShortText(cert)
		if err != nil {
			t.Fatal(err)
		}
	case tCertificateRequest:
		cert, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		result, err = CertificateRequestShortText(cert)
		if err != nil {
			t.Fatal(err)
		}
	}
	resultData := []byte(result)

	// Read the reference output
	refData, err := os.ReadFile(refFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resultData, refData) {
		t.Logf("'%s' did not match reference '%s'\n", certFile, refFile)
		t.Errorf("Dump follows:\n%s\n", result)
	}
}

// Test the root CA certificate
func TestCertInfoRoot(t *testing.T) {
	testPair(t, "test_certs/root1.cert.pem", "test_certs/root1.cert.text", tCertificate)
	testPair(t, "test_certs/root1.csr.pem", "test_certs/root1.csr.text", tCertificateRequest)
	testPairShort(t, "test_certs/root1.cert.pem", "test_certs/root1.cert.short", tCertificate)
	testPairShort(t, "test_certs/root1.csr.pem", "test_certs/root1.csr.short", tCertificateRequest)
}

// Test the leaf (user) RSA certificate
func TestCertInfoLeaf1(t *testing.T) {
	testPair(t, "test_certs/leaf1.cert.pem", "test_certs/leaf1.cert.text", tCertificate)
	testPair(t, "test_certs/leaf1.csr.pem", "test_certs/leaf1.csr.text", tCertificateRequest)
	testPairShort(t, "test_certs/leaf1.cert.pem", "test_certs/leaf1.cert.short", tCertificate)
	testPairShort(t, "test_certs/leaf1.csr.pem", "test_certs/leaf1.csr.short", tCertificateRequest)
}

// Test the leaf (user) DSA certificate
func TestCertInfoLeaf2(t *testing.T) {
	testPair(t, "test_certs/leaf2.cert.pem", "test_certs/leaf2.cert.text", tCertificate)
	testPair(t, "test_certs/leaf2.csr.pem", "test_certs/leaf2.csr.text", tCertificateRequest)
	testPairShort(t, "test_certs/leaf2.cert.pem", "test_certs/leaf2.cert.short", tCertificate)
	testPairShort(t, "test_certs/leaf2.csr.pem", "test_certs/leaf2.csr.short", tCertificateRequest)
}

// Test the leaf (user) ECDSA certificate
func TestCertInfoLeaf3(t *testing.T) {
	testPair(t, "test_certs/leaf3.cert.pem", "test_certs/leaf3.cert.text", tCertificate)
	testPair(t, "test_certs/leaf3.csr.pem", "test_certs/leaf3.csr.text", tCertificateRequest)
	testPairShort(t, "test_certs/leaf3.cert.pem", "test_certs/leaf3.cert.short", tCertificate)
	testPairShort(t, "test_certs/leaf3.csr.pem", "test_certs/leaf3.csr.short", tCertificateRequest)
}

// Test the leaf (user) with multiple sans
func TestCertInfoLeaf4(t *testing.T) {
	testPair(t, "test_certs/leaf4.cert.pem", "test_certs/leaf4.cert.text", tCertificate)
	testPair(t, "test_certs/leaf4.csr.pem", "test_certs/leaf4.csr.text", tCertificateRequest)
	testPairShort(t, "test_certs/leaf4.cert.pem", "test_certs/leaf4.cert.short", tCertificate)
	testPairShort(t, "test_certs/leaf4.csr.pem", "test_certs/leaf4.csr.short", tCertificateRequest)
}

func TestCertInfoLeaf5(t *testing.T) {
	testPair(t, "test_certs/leaf5.cert.pem", "test_certs/leaf5.cert.text", tCertificate)
	testPair(t, "test_certs/leaf5.csr.pem", "test_certs/leaf5.csr.text", tCertificateRequest)
	testPairShort(t, "test_certs/leaf5.cert.pem", "test_certs/leaf5.cert.short", tCertificate)
	testPairShort(t, "test_certs/leaf5.csr.pem", "test_certs/leaf5.csr.short", tCertificateRequest)
}

func TestCsrInfoWackyExtensions(t *testing.T) {
	testPair(t, "test_certs/x509WackyExtensions.pem", "test_certs/x509WackyExtensions.text", tCertificateRequest)
}

func TestNoCN(t *testing.T) {
	testPair(t, "test_certs/noCN.csr", "test_certs/noCN.csr.text", tCertificateRequest)
	testPairShort(t, "test_certs/noCN.csr", "test_certs/noCN.csr.text.short", tCertificateRequest)
}

func TestSigstoreCertInfo(t *testing.T) {
	testPair(t, "test_certs/sigstore1.cert.pem", "test_certs/sigstore1.cert.text", tCertificate)
	testPair(t, "test_certs/sigstore2.cert.pem", "test_certs/sigstore2.cert.text", tCertificate)
}
