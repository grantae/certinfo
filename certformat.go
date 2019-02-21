package certinfo

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"strconv"
	"time"

	"github.com/smallstep/cli/pkg/x509"
	"golang.org/x/crypto/ed25519"
)

// formatBuffer is a helper to write using sprintf.
type formatBuffer struct {
	bytes.Buffer
}

// Writef writes a string formated using fmt.Sprintf.
func (b *formatBuffer) Writef(format string, args ...interface{}) (int, error) {
	return b.Buffer.WriteString(fmt.Sprintf(format, args...))
}

type certificateShort struct {
	Type               string
	PublicKeyAlgorithm string
	SerialNumber       string
	Subject            string
	Issuer             string
	SANs               []string
	Provisioner        *provisioner
	NotBefore          time.Time
	NotAfter           time.Time
}

type provisioner struct {
	ID   string
	Name string
}

func newCertificateShort(cert *x509.Certificate) *certificateShort {
	var typ string
	if cert.IsCA {
		if cert.CheckSignatureFrom(cert) == nil {
			typ = "Root CA"
		} else {
			typ = "Intermediate CA"
		}
	} else {
		typ = "TLS"
	}

	return &certificateShort{
		Type:               typ,
		PublicKeyAlgorithm: getPublicKeyAlgorithm(cert.PublicKeyAlgorithm, cert.PublicKey),
		SerialNumber:       abbreviated(cert.SerialNumber.String()),
		Subject:            cert.Subject.CommonName,
		Issuer:             cert.Issuer.CommonName,
		SANs:               getSANs(cert),
		Provisioner:        getProvisioner(cert),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
	}
}

// String returns the certificateShort formated as a string.
func (c *certificateShort) String() string {
	var buf formatBuffer
	buf.Writef("X.509v3 %s Certificate (%s) [Serial: %s]\n", c.Type, c.PublicKeyAlgorithm, c.SerialNumber)
	buf.Writef("  Subject:     %s\n", c.Subject)
	for _, s := range c.SANs {
		buf.Writef("               %s\n", s)
	}
	buf.Writef("  Issuer:      %s\n", c.Issuer)
	if c.Provisioner != nil {
		buf.Writef("  Provisioner: %s [ID: %s]\n", c.Provisioner.Name, c.Provisioner.ID)
	}
	buf.Writef("  Valid from:  %s\n", c.NotBefore.Format(time.RFC3339))
	buf.Writef("          to:  %s\n", c.NotAfter.Format(time.RFC3339))
	return buf.String()
}

type certificateRequestShort struct {
	PublicKeyAlgorithm string
	Subject            string
	SANs               []string
}

func newCertificateRequestShort(cr *x509.CertificateRequest) *certificateRequestShort {
	var sans []string
	for _, s := range cr.DNSNames {
		if s != cr.Subject.CommonName {
			sans = append(sans, s)
		}
	}
	for _, ip := range cr.IPAddresses {
		if s := ip.String(); s != cr.Subject.CommonName {
			sans = append(sans, s)
		}
	}
	for _, s := range cr.EmailAddresses {
		if s != cr.Subject.CommonName {
			sans = append(sans, s)
		}
	}
	for _, uri := range cr.URIs {
		if s := uri.String(); s != cr.Subject.CommonName {
			sans = append(sans, s)
		}
	}
	return &certificateRequestShort{
		PublicKeyAlgorithm: getPublicKeyAlgorithm(cr.PublicKeyAlgorithm, cr.PublicKey),
		Subject:            cr.Subject.CommonName,
		SANs:               sans,
	}
}

// String returns the certificateShort formated as a string.
func (c *certificateRequestShort) String() string {
	var buf formatBuffer
	buf.Writef("X.509v3 Certificate Signing Request (%s)\n", c.PublicKeyAlgorithm)
	buf.Writef("  Subject:     %s\n", c.Subject)
	for _, s := range c.SANs {
		buf.Writef("               %s\n", s)
	}
	return buf.String()
}

func getSANs(cert *x509.Certificate) []string {
	var sans []string
	for _, s := range cert.DNSNames {
		if s != cert.Subject.CommonName {
			sans = append(sans, s)
		}
	}
	for _, ip := range cert.IPAddresses {
		if s := ip.String(); s != cert.Subject.CommonName {
			sans = append(sans, s)
		}
	}
	for _, s := range cert.EmailAddresses {
		if s != cert.Subject.CommonName {
			sans = append(sans, s)
		}
	}
	for _, uri := range cert.URIs {
		if s := uri.String(); s != cert.Subject.CommonName {
			sans = append(sans, s)
		}
	}
	return sans
}

func getProvisioner(cert *x509.Certificate) *provisioner {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidStepProvisioner) {
			val := &stepProvisioner{}
			rest, err := asn1.Unmarshal(ext.Value, val)
			if err != nil || len(rest) > 0 {
				return nil
			}

			return &provisioner{
				ID:   abbreviated(string(val.CredentialID)),
				Name: string(val.Name),
			}
		}
	}
	return nil
}

func getPublicKeyAlgorithm(algorithm x509.PublicKeyAlgorithm, key interface{}) string {
	var params string
	switch pk := key.(type) {
	case *ecdsa.PublicKey:
		params = pk.Curve.Params().Name
	case *rsa.PublicKey:
		params = strconv.Itoa(pk.Size() * 8)
	case *dsa.PublicKey:
		params = strconv.Itoa(pk.Q.BitLen())
	case ed25519.PublicKey:
		params = strconv.Itoa(len(pk) * 8)
	default:
		params = "unknown"
	}
	return fmt.Sprintf("%s %s", algorithm, params)
}

func abbreviated(s string) string {
	l := len(s)
	if l <= 8 {
		return s
	}
	return s[:4] + "..." + s[l-4:]
}
