package certinfo

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFormatter(t *testing.T) {
	pemData, err := ioutil.ReadFile("test_certs/root1.cert.pem")
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

	oid := asn1.ObjectIdentifier{1, 2, 3, 4}

	cert.Extensions = append(cert.Extensions, pkix.Extension{
		Id:    oid,
		Value: []byte("foo"),
	})

	got, err := CertificateText(cert, WithFormatter(oid, func(ext pkix.Extension) string {
		return fmt.Sprintf("Custom:\n%4s%s", "", string(ext.Value))
	}))
	if err != nil {
		t.Fatal(err)
	}

	want, err := os.ReadFile("test_certs/root1.cert.customfield.text")
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(string(want), got); diff != "" {
		t.Log(got)
		t.Error(diff)
	}
}
