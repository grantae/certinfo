package certinfo

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"reflect"
	"testing"
	"time"
)

func Test_newCertificateShort(t *testing.T) {
	type args struct {
		filename string
	}
	tests := []struct {
		name string
		args args
		want *certificateShort
	}{
		{"root1", args{"test_certs/root1.cert.pem"}, &certificateShort{
			Type:               "Root CA",
			SerialNumber:       "1",
			PublicKeyAlgorithm: "RSA 512",
			Subject:            "worldwidgetauthority.com",
			Issuer:             "worldwidgetauthority.com",
			NotBefore:          mustParseTime(t, "2020-07-23T18:56:47Z"),
			NotAfter:           mustParseTime(t, "2040-06-30T07:37:21Z"),
		}},
		{"leaf1", args{"test_certs/leaf1.cert.pem"}, &certificateShort{
			Type:               "TLS",
			SerialNumber:       "2",
			PublicKeyAlgorithm: "RSA 512",
			Subject:            "southernwidgets.com",
			Issuer:             "worldwidgetauthority.com",
			NotBefore:          mustParseTime(t, "2020-07-23T18:56:47Z"),
			NotAfter:           mustParseTime(t, "2040-06-30T07:37:21Z"),
		}},
		{"leaf2", args{"test_certs/leaf2.cert.pem"}, &certificateShort{
			Type:               "TLS",
			SerialNumber:       "3",
			PublicKeyAlgorithm: "DSA 160",
			Subject:            "northernwidgets.com",
			Issuer:             "worldwidgetauthority.com",
			NotBefore:          mustParseTime(t, "2020-07-23T18:56:47Z"),
			NotAfter:           mustParseTime(t, "2040-06-30T07:37:21Z"),
		}},
		{"leaf3", args{"test_certs/leaf3.cert.pem"}, &certificateShort{
			Type:               "TLS",
			SerialNumber:       "4",
			PublicKeyAlgorithm: "ECDSA P-256",
			Subject:            "subsaharanwidgets.com",
			Issuer:             "worldwidgetauthority.com",
			NotBefore:          mustParseTime(t, "2020-07-23T18:56:47Z"),
			NotAfter:           mustParseTime(t, "2040-06-30T07:37:21Z"),
		}},
		{"leaf5", args{"test_certs/leaf5.cert.pem"}, &certificateShort{
			Type:               "TLS",
			SerialNumber:       "1",
			PublicKeyAlgorithm: "ECDSA P-521",
			Subject:            "subsaharanwidgets.com",
			Issuer:             "worldwidgetauthority.com",
			NotBefore:          mustParseTime(t, "2020-07-23T18:56:47Z"),
			NotAfter:           mustParseTime(t, "2040-06-30T07:37:21Z"),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := mustParseCertificate(t, tt.args.filename)
			if got := newCertificateShort(cert); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newCertificateShort() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_newCertificateRequestShort(t *testing.T) {
	type args struct {
		filename string
	}
	tests := []struct {
		name string
		args args
		want *certificateRequestShort
	}{
		{"root1", args{"test_certs/root1.csr.pem"}, &certificateRequestShort{
			PublicKeyAlgorithm: "RSA 512",
			Subject:            "worldwidgetauthority.com",
		}},
		{"leaf1", args{"test_certs/leaf1.csr.pem"}, &certificateRequestShort{
			PublicKeyAlgorithm: "RSA 512",
			Subject:            "southernwidgets.com",
		}},
		{"leaf2", args{"test_certs/leaf2.csr.pem"}, &certificateRequestShort{
			PublicKeyAlgorithm: "DSA 160",
			Subject:            "northernwidgets.com",
		}},
		{"leaf3", args{"test_certs/leaf3.csr.pem"}, &certificateRequestShort{
			PublicKeyAlgorithm: "ECDSA P-256",
			Subject:            "subsaharanwidgets.com",
		}},
		{"leaf5", args{"test_certs/leaf5.csr.pem"}, &certificateRequestShort{
			PublicKeyAlgorithm: "ECDSA P-521",
			Subject:            "subsaharanwidgets.com",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr := mustParseCertificateRequest(t, tt.args.filename)
			if got := newCertificateRequestShort(cr); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newCertificateRequestShort() = %v, want %v", got, tt.want)
			}
		})
	}
}

func mustParseTime(t *testing.T, s string) time.Time {
	tt, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return tt
}

func mustParseCertificate(t *testing.T, filename string) *x509.Certificate {
	pemData, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("failed to read %s: %v", filename, err)
	}
	block, rest := pem.Decode(pemData)
	if block == nil || len(rest) > 0 || len(block.Bytes) == 0 {
		t.Fatalf("failed to decode PEM in %s", filename)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate in %s: %v", filename, err)
	}
	return cert
}

func mustParseCertificateRequest(t *testing.T, filename string) *x509.CertificateRequest {
	pemData, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("failed to read %s: %v", filename, err)
	}
	block, rest := pem.Decode(pemData)
	if block == nil || len(rest) > 0 || len(block.Bytes) == 0 {
		t.Fatalf("failed to decode PEM in %s", filename)
	}
	cr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate request in %s: %v", filename, err)
	}
	return cr
}
