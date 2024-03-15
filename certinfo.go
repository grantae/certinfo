package certinfo

import (
	"bytes"
	"crypto/dsa" //nolint:staticcheck // used to inspect key
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"time"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	ctutil "github.com/google/certificate-transparency-go/x509util"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Time formats used
const (
	validityTimeFormat = "Jan 2 15:04:05 2006 MST"
	sctTimeFormat      = "Jan 2 15:04:05.000 2006 MST"
)

// Extra ASN1 OIDs that we may need to handle
var (
	oidEmailAddress                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	oidDomainComponent                = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
	oidUserID                         = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
	oidExtensionAuthorityInfoAccess   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidNSComment                      = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 13}
	oidStepProvisioner                = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1}
	oidStepCertificateAuthority       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 2}
	oidStepManagedEndpoint            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 3}
	oidSignedCertificateTimestampList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	oidPermanentIdentifier            = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3}
	oidHardwareModuleName             = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 4}
	oidUserPrincipalName              = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
)

// Sigstore (Fulcio) OIDs as documented here: https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
var (
	oidSigstoreOIDCIssuer               = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidSigstoreGithubWorkflowTrigger    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 2}
	oidSigstoreGithubWorkflowSha        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 3}
	oidSigstoreGithubWorkflowName       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 4}
	oidSigstoreGithubWorkflowRepository = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 5}
	oidSigstoreGithubWorkflowRef        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 6}
	oidSigstoreOtherName                = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 7}
)

// TCG EK Credential Profile For TPM Family 2.0; Level 0
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p4_r3.pdf
var (
	oidTPMManufacturer  = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidTPMModel         = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	oidTPMVersion       = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
	oidTPMSpecification = asn1.ObjectIdentifier{2, 23, 133, 2, 16}
)

// stepProvisionerType are string representation of the provisioner type (int)
// in the step provisioner extension.
var stepProvisionerType = [...]string{
	"NOOP",   // Type 0, is not supported
	"JWK",    // Type 1
	"OIDC",   // Type 2
	"GCP",    // Type 3
	"AWS",    // Type 4
	"Azure",  // Type 5
	"ACME",   // Type 6
	"X5C",    // Type 7
	"K8sSA",  // Type 8
	"SSHPOP", // Type 9
	"SCEP",   // Type 10
	"Nebula", // Type 11
}

// stepManagedEndpointKind are string representations of the managed endpoint kind (int)
// in the step managed endpoint extension.
var stepManagedEndpointKind = [...]string{
	"Unknown",  // Type 0, is not supported
	"Device",   // Type 1
	"Workload", // Type 2
	"People",   // Type 3
}

// validity allows unmarshaling the certificate validity date range
type validity struct {
	NotBefore, NotAfter time.Time
}

type stepProvisioner struct {
	Type          int
	Name          []byte
	CredentialID  []byte
	KeyValuePairs []string `asn1:"optional,omitempty"`
}

type stepCertificateAuthority struct {
	Type          string
	CertificateID string   `asn1:"optional,omitempty"`
	KeyValuePairs []string `asn1:"optional,omitempty"`
}

type stepManagedEndpoint struct {
	Kind       int
	EndpointID string
}

// RFC 5280 - https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
//
//	OtherName ::= SEQUENCE {
//	  type-id    OBJECT IDENTIFIER,
//	  value      [0] EXPLICIT ANY DEFINED BY type-id }
type otherName struct {
	TypeID asn1.ObjectIdentifier
	Value  asn1.RawValue
}

// permanentIdentifier is defined in RFC 4043 as an optional feature that
// may be used by a CA to indicate that two or more certificates relate to the
// same entity.
//
// The OID defined for this SAN is "1.3.6.1.5.5.7.8.3".
//
// See https://www.rfc-editor.org/rfc/rfc4043
//
//	PermanentIdentifier ::= SEQUENCE {
//	  identifierValue    UTF8String OPTIONAL,
//	  assigner           OBJECT IDENTIFIER OPTIONAL
//	}
type permanentIdentifier struct {
	IdentifierValue string                `asn1:"utf8,optional"`
	Assigner        asn1.ObjectIdentifier `asn1:"optional"`
}

// hardwareModuleName is defined in RFC 4108 as an optional feature that by be
// used to identify a hardware module.
//
// The OID defined for this SAN is "1.3.6.1.5.5.7.8.4".
//
// See https://www.rfc-editor.org/rfc/rfc4108#section-5
//
//	HardwareModuleName ::= SEQUENCE {
//	  hwType OBJECT IDENTIFIER,
//	  hwSerialNum OCTET STRING
//	}
type hardwareModuleName struct {
	Type         asn1.ObjectIdentifier
	SerialNumber []byte `asn1:"tag:4"`
}

// userPrincipalName or UPN is Microsoft Active Directory attribute that you typically
// see expressed as an email address.
//
// The userPrincipalName is defined in MSDN,
// https://docs.microsoft.com/en-us/windows/win32/adschema/a-userprincipalname
//
// The OID defined for this SAN is "1.3.6.1.4.1.311.20.2.3".
type userPrincipalName struct {
	UPN string `asn1:"utf8"`
}

type tpmDeviceAttributes struct {
	Attributes []asn1.RawValue
}

// tpmDeviceAttribute defines the tpm attributes TPMManufacturer, TPMModel and
// TPMVersion.
//
// These attributes are defined in section 3.1.2 of
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p4_r3.pdf
//
//	TPMManufacturer ATTRIBUTE ::= {
//	    WITH SYNTAX UTF8String
//	    ID tcg-at-tpmManufacturer }
//	TPMModel ATTRIBUTE ::= {
//	    WITH SYNTAX UTF8String
//	    ID tcg-at-tpmModel }
//	TPMVersion ATTRIBUTE ::= {
//	    WITH SYNTAX UTF8String
//	    ID tcg-at-tpmVersion }
type tpmDeviceAttribute struct {
	ID    asn1.ObjectIdentifier
	Value string `asn1:"utf8"`
}

type subjectDirectoryAttributes struct {
	Attribute attribute
}

type attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

// tpmSpecification identifies the TPM family, level and revision of the TPM
// specification with which a TPM implementation is compliant.
//
// It is defined in section 3.1.3 of
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p4_r3.pdf
//
//	TPMSpecification ::= SEQUENCE {
//		family UTF8String (SIZE (1..STRMAX)),
//		level INTEGER,
//		revision INTEGER }
type tpmSpecification struct {
	Family   string `asn1:"utf8"`
	Level    int
	Revision int
}

// publicKeyInfo allows unmarshaling the public key
type publicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// tbsCertificate allows unmarshaling of the "To-Be-Signed" principle portion
// of the certificate
type tbsCertificate struct {
	Version            int `asn1:"optional,explicit,default:1,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueID           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueID    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

// certUniqueIDs extracts the subject and issuer unique IDs which are
// byte strings. These are not common but may be present in x509v2 certificates
// or later under tags 1 and 2 (before x509v3 extensions).
func certUniqueIDs(tbsAsnData []byte) (issuerUniqueID, subjectUniqueID []byte, err error) {
	var tbs tbsCertificate
	rest, err := asn1.Unmarshal(tbsAsnData, &tbs)
	if err != nil {
		return nil, nil, err
	}
	if len(rest) > 0 {
		return nil, nil, asn1.SyntaxError{Msg: "trailing data"}
	}
	iuid := tbs.UniqueID.RightAlign()
	suid := tbs.SubjectUniqueID.RightAlign()
	return iuid, suid, err
}

// printName prints the fields of a distinguished name, which include such
// things as its common name and locality.
func printName(names []pkix.AttributeTypeAndValue, buf *bytes.Buffer) []string {
	values := []string{}
	for _, name := range names {
		oid := name.Type
		switch {
		case len(oid) == 4 && oid[0] == 2 && oid[1] == 5 && oid[2] == 4:
			switch oid[3] {
			case 3:
				values = append(values, fmt.Sprintf("CN=%s", name.Value))
			case 5:
				values = append(values, fmt.Sprintf("SERIALNUMBER=%s", name.Value))
			case 6:
				values = append(values, fmt.Sprintf("C=%s", name.Value))
			case 7:
				values = append(values, fmt.Sprintf("L=%s", name.Value))
			case 8:
				values = append(values, fmt.Sprintf("ST=%s", name.Value))
			case 9:
				values = append(values, fmt.Sprintf("STREET=%s", name.Value))
			case 10:
				values = append(values, fmt.Sprintf("O=%s", name.Value))
			case 11:
				values = append(values, fmt.Sprintf("OU=%s", name.Value))
			case 17:
				values = append(values, fmt.Sprintf("POSTALCODE=%s", name.Value))
			default:
				values = append(values, fmt.Sprintf("UnknownOID=%s", name.Type.String()))
			}
		case oid.Equal(oidEmailAddress):
			values = append(values, fmt.Sprintf("emailAddress=%s", name.Value))
		case oid.Equal(oidDomainComponent):
			values = append(values, fmt.Sprintf("DC=%s", name.Value))
		case oid.Equal(oidUserID):
			values = append(values, fmt.Sprintf("UID=%s", name.Value))
		default:
			values = append(values, fmt.Sprintf("UnknownOID=%s", name.Type.String()))
		}
	}
	if len(values) > 0 {
		fmt.Fprint(buf, values[0])
		for i := 1; i < len(values); i++ {
			fmt.Fprint(buf, ","+values[i])
		}
		fmt.Fprint(buf, "\n")
	}
	return values
}

// dsaKeyPrinter formats the Y, P, Q, or G components of a DSA public key.
func dsaKeyPrinter(name string, val *big.Int, buf *bytes.Buffer) {
	fmt.Fprintf(buf, "%16s%s:", "", name)
	for i, b := range val.Bytes() {
		if (i % 15) == 0 {
			fmt.Fprintf(buf, "\n%20s", "")
		}
		fmt.Fprintf(buf, "%02x", b)
		if i != len(val.Bytes())-1 {
			fmt.Fprint(buf, ":")
		}
	}
	fmt.Fprint(buf, "\n")
}

func printVersion(version int, buf *bytes.Buffer) {
	hexVersion := version - 1
	if hexVersion < 0 {
		hexVersion = 0
	}
	fmt.Fprintf(buf, "%8sVersion: %d (%#x)\n", "", version, hexVersion)
}

func printSubjectInformation(subj *pkix.Name, pkAlgo x509.PublicKeyAlgorithm, pk interface{}, buf *bytes.Buffer) error {
	fmt.Fprintf(buf, "%8sSubject:", "")
	if len(subj.Names) > 0 {
		fmt.Fprint(buf, " ")
		printName(subj.Names, buf)
	} else {
		fmt.Fprint(buf, "\n")
	}
	fmt.Fprintf(buf, "%8sSubject Public Key Info:\n%12sPublic Key Algorithm: ", "", "")
	switch pkAlgo {
	case x509.RSA:
		fmt.Fprint(buf, "RSA\n")
		if rsaKey, ok := pk.(*rsa.PublicKey); ok {
			fmt.Fprintf(buf, "%16sPublic-Key: (%d bit)\n", "", rsaKey.N.BitLen())
			// Some implementations (notably OpenSSL) prepend 0x00 to the modulus
			// if its most-significant bit is set. There is no need to do that here
			// because the modulus is always unsigned and the extra byte can be
			// confusing given the bit length.
			fmt.Fprintf(buf, "%16sModulus:", "")
			for i, val := range rsaKey.N.Bytes() {
				if (i % 15) == 0 {
					fmt.Fprintf(buf, "\n%20s", "")
				}
				fmt.Fprintf(buf, "%02x", val)
				if i != len(rsaKey.N.Bytes())-1 {
					fmt.Fprint(buf, ":")
				}
			}
			fmt.Fprintf(buf, "\n%16sExponent: %d (%#x)\n", "", rsaKey.E, rsaKey.E)
		} else {
			return errors.New("certinfo: Expected rsa.PublicKey for type x509.RSA")
		}
	case x509.DSA:
		fmt.Fprint(buf, "DSA\n")
		if dsaKey, ok := pk.(*dsa.PublicKey); ok {
			dsaKeyPrinter("pub", dsaKey.Y, buf)
			dsaKeyPrinter("P", dsaKey.P, buf)
			dsaKeyPrinter("Q", dsaKey.Q, buf)
			dsaKeyPrinter("G", dsaKey.G, buf)
		} else {
			return errors.New("certinfo: Expected dsa.PublicKey for type x509.DSA")
		}
	case x509.ECDSA:
		fmt.Fprint(buf, "ECDSA\n")
		if ecdsaKey, ok := pk.(*ecdsa.PublicKey); ok {
			fmt.Fprintf(buf, "%16sPublic-Key: (%d bit)\n", "", ecdsaKey.Params().BitSize)
			dsaKeyPrinter("X", ecdsaKey.X, buf)
			dsaKeyPrinter("Y", ecdsaKey.Y, buf)
			fmt.Fprintf(buf, "%16sCurve: %s\n", "", ecdsaKey.Params().Name)
		} else {
			return errors.New("certinfo: Expected ecdsa.PublicKey for type x509.DSA")
		}
	case x509.Ed25519:
		fmt.Fprint(buf, "Ed25519\n")
		if ed25519Key, ok := pk.(ed25519.PublicKey); ok {
			fmt.Fprintf(buf, "%16sPublic-Key: (%d bit)", "", len(ed25519Key))
			for i, b := range ed25519Key {
				if (i % 15) == 0 {
					fmt.Fprintf(buf, "\n%20s", "")
				}
				fmt.Fprintf(buf, "%02x", b)
				if i != len(ed25519Key)-1 {
					fmt.Fprint(buf, ":")
				}
			}
			fmt.Fprint(buf, "\n")
		} else {
			return errors.New("certinfo: Expected ed25519.PublicKey for type x509.ED25519")
		}
	default:
		return errors.New("certinfo: Unknown public key type")
	}
	return nil
}

func printSubjKeyID(ext pkix.Extension, buf *bytes.Buffer) error {
	// subjectKeyIdentifier: RFC 5280, 4.2.1.2
	fmt.Fprintf(buf, "%12sX509v3 Subject Key Identifier:", "")
	if ext.Critical {
		fmt.Fprint(buf, " critical\n")
	} else {
		fmt.Fprint(buf, "\n")
	}
	var subjectKeyID []byte
	if _, err := asn1.Unmarshal(ext.Value, &subjectKeyID); err != nil {
		return err
	}
	for i := 0; i < len(subjectKeyID); i++ {
		if i == 0 {
			fmt.Fprintf(buf, "%16s%02X", "", subjectKeyID[0])
		} else {
			fmt.Fprintf(buf, ":%02X", subjectKeyID[i])
		}
	}
	fmt.Fprint(buf, "\n")
	return nil
}

func forEachSAN(der cryptobyte.String, callback func(tag int, data []byte) error) error {
	if !der.ReadASN1(&der, cryptobyte_asn1.SEQUENCE) {
		return errors.New("invalid subject alternative names")
	}
	for !der.Empty() {
		var san cryptobyte.String
		var tag cryptobyte_asn1.Tag
		if !der.ReadAnyASN1Element(&san, &tag) {
			return errors.New("invalid subject alternative name")
		}
		if err := callback(int(tag^0x80), san); err != nil {
			return err
		}
	}

	return nil
}

func printOtherName(on otherName, buf *bytes.Buffer) {
	fmt.Fprintf(buf, "%16sOtherName: Type: %s", "", on.TypeID)
	fmt.Fprintf(buf, ", Value: 0x%x", on.Value.Bytes)
	fmt.Fprint(buf, "\n")
}

func printSubjAltNames(ext pkix.Extension, dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL, buf *bytes.Buffer) error {
	// subjectAltName: RFC 5280, 4.2.1.6
	// TODO: Currently crypto/x509 only extracts DNS, email, and IP addresses.
	// We should add the others to it or implement them here.
	fmt.Fprintf(buf, "%12sX509v3 Subject Alternative Name:", "")
	if ext.Critical {
		fmt.Fprint(buf, " critical\n")
	} else {
		fmt.Fprint(buf, "\n")
	}
	if len(dnsNames) > 0 {
		fmt.Fprintf(buf, "%16sDNS:%s", "", dnsNames[0])
		for i := 1; i < len(dnsNames); i++ {
			fmt.Fprintf(buf, ", DNS:%s", dnsNames[i])
		}
		fmt.Fprint(buf, "\n")
	}
	if len(emailAddresses) > 0 {
		fmt.Fprintf(buf, "%16semail:%s", "", emailAddresses[0])
		for i := 1; i < len(emailAddresses); i++ {
			fmt.Fprintf(buf, ", email:%s", emailAddresses[i])
		}
		fmt.Fprint(buf, "\n")
	}
	if len(ipAddresses) > 0 {
		fmt.Fprintf(buf, "%16sIP Address:%s", "", ipAddresses[0].String()) // XXX verify string format
		for i := 1; i < len(ipAddresses); i++ {
			fmt.Fprintf(buf, ", IP Address:%s", ipAddresses[i].String())
		}
		fmt.Fprint(buf, "\n")
	}
	if len(uris) > 0 {
		fmt.Fprintf(buf, "%16sURI:%s", "", uris[0].String())
		for i := 1; i < len(uris); i++ {
			fmt.Fprintf(buf, ", URI:%s", uris[i].String())
		}
		fmt.Fprint(buf, "\n")
	}

	// Parse other names ignoring errors
	return forEachSAN(ext.Value, func(tag int, data []byte) error {
		switch tag {
		case 0, 0x20:
			var on otherName
			if rest, err := asn1.UnmarshalWithParams(data, &on, "tag:0"); err != nil || len(rest) > 0 {
				return nil //nolint:nilerr // ignore errors as instructed above
			}

			switch {
			case on.TypeID.Equal(oidPermanentIdentifier):
				var pi permanentIdentifier
				if _, err := asn1.Unmarshal(on.Value.Bytes, &pi); err != nil {
					printOtherName(on, buf)
					return nil //nolint:nilerr // ignore errors as instructed above
				}
				if pi.IdentifierValue != "" {
					fmt.Fprintf(buf, "%16sPermanent Identifier: %s", "", pi.IdentifierValue)
				}
				if len(pi.Assigner) > 0 {
					fmt.Fprintf(buf, ", Assigner: %s", pi.Assigner.String())
				}
				fmt.Fprint(buf, "\n")
			case on.TypeID.Equal(oidHardwareModuleName):
				var hmn hardwareModuleName
				if _, err := asn1.Unmarshal(on.Value.Bytes, &hmn); err != nil {
					printOtherName(on, buf)
					return nil //nolint:nilerr // ignore errors as instructed above
				}
				fmt.Fprintf(buf, "%16sHardware Module Name: Type: %s", "", hmn.Type.String())
				fmt.Fprintf(buf, ", Serial Number: %s", hmn.SerialNumber)
				fmt.Fprint(buf, "\n")
			case on.TypeID.Equal(oidUserPrincipalName):
				var upn userPrincipalName
				if _, err := asn1.UnmarshalWithParams(on.Value.Bytes, &upn.UPN, "utf8"); err != nil {
					printOtherName(on, buf)
					return nil //nolint:nilerr // ignore errors as instructed above
				}
				fmt.Fprintf(buf, "%16sUPN: %s", "", upn.UPN)
				fmt.Fprint(buf, "\n")
			case on.TypeID.Equal(oidSigstoreOtherName):
				var son string
				if _, err := asn1.Unmarshal(on.Value.Bytes, &son); err != nil {
					printOtherName(on, buf)
					return nil //nolint:nilerr // ignore errors as instructed above
				}
				fmt.Fprintf(buf, "%16sSigstore Identity: %s", "", son)
				fmt.Fprint(buf, "\n")
			default:
				printOtherName(on, buf)
			}
		case 0x24:
			var tpm tpmDeviceAttributes
			if rest, err := asn1.UnmarshalWithParams(data, &tpm, "tag:4"); err != nil || len(rest) > 0 {
				return nil //nolint:nilerr // ignore errors as instructed above
			}
			for _, r := range tpm.Attributes {
				var attr tpmDeviceAttribute
				if _, err := asn1.Unmarshal(r.Bytes, &attr); err != nil {
					continue
				}
				switch {
				case attr.ID.Equal(oidTPMManufacturer):
					fmt.Fprintf(buf, "%16sTPM Manufacturer: %s", "", attr.Value)
					fmt.Fprint(buf, "\n")
				case attr.ID.Equal(oidTPMModel):
					fmt.Fprintf(buf, "%16sTPM Model: %s", "", attr.Value)
					fmt.Fprint(buf, "\n")
				case attr.ID.Equal(oidTPMVersion):
					fmt.Fprintf(buf, "%16sTPM Version: %s", "", attr.Value)
					fmt.Fprint(buf, "\n")
				}
			}
		}
		return nil
	})
}

func printSignature(sigAlgo x509.SignatureAlgorithm, sig []byte, buf *bytes.Buffer) {
	fmt.Fprintf(buf, "%4sSignature Algorithm: %s", "", sigAlgo)
	for i, val := range sig {
		if (i % 18) == 0 {
			fmt.Fprintf(buf, "\n%9s", "")
		}
		fmt.Fprintf(buf, "%02x", val)
		if i != len(sig)-1 {
			fmt.Fprint(buf, ":")
		}
	}
	fmt.Fprint(buf, "\n")
}

func toBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func printSCTSignature(sig ct.DigitallySigned, buf *bytes.Buffer) {
	fmt.Fprintf(buf, "%20sSignature Algorithm: %s-%s", "", sig.Algorithm.Hash, sig.Algorithm.Signature)
	for i, val := range sig.Signature {
		if (i % 18) == 0 {
			fmt.Fprintf(buf, "\n%22s", "")
		}
		fmt.Fprintf(buf, "%02x", val)
		if i != len(sig.Signature)-1 {
			fmt.Fprint(buf, ":")
		}
	}
	fmt.Fprint(buf, "\n")
}

func printExtensionHeader(name string, ext pkix.Extension, buf *bytes.Buffer) {
	fmt.Fprintf(buf, "%12s%s:", "", name)
	if ext.Critical {
		fmt.Fprint(buf, " critical\n")
	} else {
		fmt.Fprint(buf, "\n")
	}
}

func printRunes(ext pkix.Extension, buf *bytes.Buffer) {
	value := bytes.Runes(ext.Value)
	sanitized := make([]rune, len(value))
	for i, r := range value {
		if strconv.IsPrint(r) && r != '�' {
			sanitized[i] = r
		} else {
			sanitized[i] = '.'
		}
	}
	fmt.Fprintf(buf, "%16s%s\n", "", string(sanitized))
}

// CertificateShortText returns the human-readable string representation of the
// given cert using a short and friendly format.
func CertificateShortText(cert *x509.Certificate) (string, error) {
	return newCertificateShort(cert).String(), nil
}

// CertificateRequestShortText returns the human-readable string representation
// of the given certificate request using a short and friendly format.
func CertificateRequestShortText(cr *x509.CertificateRequest) (string, error) {
	return newCertificateRequestShort(cr).String(), nil
}

// CertificateText returns a human-readable string representation
// of the certificate cert. The format is similar (but not identical)
// to the OpenSSL way of printing certificates.
func CertificateText(cert *x509.Certificate) (string, error) {
	var (
		bbuf bytes.Buffer
	)
	bbuf.Grow(4096) // 4KiB should be enough
	buf := &bbuf

	fmt.Fprint(buf, "Certificate:\n")
	fmt.Fprintf(buf, "%4sData:\n", "")
	printVersion(cert.Version, buf)
	fmt.Fprintf(buf, "%8sSerial Number: %d (%#x)\n", "", cert.SerialNumber, cert.SerialNumber.Bytes())
	fmt.Fprintf(buf, "%4sSignature Algorithm: %s\n", "", cert.SignatureAlgorithm)

	// Issuer information
	fmt.Fprintf(buf, "%8sIssuer: ", "")
	printName(cert.Issuer.Names, buf)

	// Validity information
	fmt.Fprintf(buf, "%8sValidity\n", "")
	fmt.Fprintf(buf, "%12sNot Before: %s\n", "", cert.NotBefore.Format(validityTimeFormat))
	fmt.Fprintf(buf, "%12sNot After : %s\n", "", cert.NotAfter.Format(validityTimeFormat))

	// Subject information
	err := printSubjectInformation(&cert.Subject, cert.PublicKeyAlgorithm, cert.PublicKey, buf)
	if err != nil {
		return "", err
	}

	// Issuer/Subject Unique ID, typically used in old v2 certificates
	issuerUID, subjectUID, err := certUniqueIDs(cert.RawTBSCertificate)
	if err != nil {
		return "", fmt.Errorf("certinfo: Error parsing TBS unique attributes: %w", err)
	}
	if len(issuerUID) > 0 {
		fmt.Fprintf(buf, "%8sIssuer Unique ID: %02x", "", issuerUID[0])
		for i := 1; i < len(issuerUID); i++ {
			fmt.Fprintf(buf, ":%02x", issuerUID[i])
		}
		fmt.Fprint(buf, "\n")
	}
	if len(subjectUID) > 0 {
		fmt.Fprintf(buf, "%8sSubject Unique ID: %02x", "", subjectUID[0])
		for i := 1; i < len(subjectUID); i++ {
			fmt.Fprintf(buf, ":%02x", subjectUID[i])
		}
		fmt.Fprint(buf, "\n")
	}

	// Optional extensions for X509v3
	if cert.Version == 3 && len(cert.Extensions) > 0 {
		fmt.Fprintf(buf, "%8sX509v3 extensions:\n", "")
		for _, ext := range cert.Extensions {
			//nolint:gocritic // avoid nested switch statements
			if len(ext.Id) == 4 && ext.Id[0] == 2 && ext.Id[1] == 5 && ext.Id[2] == 29 {
				switch ext.Id[3] {
				case 9:
					fmt.Fprintf(buf, "%12sX509v3 Subject Directory Attributes:", "")
					if ext.Critical {
						fmt.Fprint(buf, " critical\n")
					} else {
						fmt.Fprint(buf, "\n")
					}
					var sda subjectDirectoryAttributes
					if rest, err := asn1.Unmarshal(ext.Value, &sda); err != nil || len(rest) > 0 {
						printRunes(ext, buf)
						continue
					}

					if sda.Attribute.Type.Equal(oidTPMSpecification) {
						var spec tpmSpecification
						if _, err := asn1.Unmarshal(sda.Attribute.Value.Bytes, &spec); err == nil {
							fmt.Fprintf(buf, "%16sTPM Specification: Family: %s, Level: %d, Revision: %d\n", "", spec.Family, spec.Level, spec.Revision)
							continue
						}
					}
					fmt.Fprintf(buf, "%16s%s: 0x%x\n", "", sda.Attribute.Type, sda.Attribute.Value.Bytes)
				case 14:
					err = printSubjKeyID(ext, buf)
				case 15:
					// keyUsage: RFC 5280, 4.2.1.3
					fmt.Fprintf(buf, "%12sX509v3 Key Usage:", "")
					if ext.Critical {
						fmt.Fprint(buf, " critical\n")
					} else {
						fmt.Fprint(buf, "\n")
					}
					usages := []string{}
					if cert.KeyUsage&x509.KeyUsageDigitalSignature > 0 {
						usages = append(usages, "Digital Signature")
					}
					if cert.KeyUsage&x509.KeyUsageContentCommitment > 0 {
						usages = append(usages, "Content Commitment")
					}
					if cert.KeyUsage&x509.KeyUsageKeyEncipherment > 0 {
						usages = append(usages, "Key Encipherment")
					}
					if cert.KeyUsage&x509.KeyUsageDataEncipherment > 0 {
						usages = append(usages, "Data Encipherment")
					}
					if cert.KeyUsage&x509.KeyUsageKeyAgreement > 0 {
						usages = append(usages, "Key Agreement")
					}
					if cert.KeyUsage&x509.KeyUsageCertSign > 0 {
						usages = append(usages, "Certificate Sign")
					}
					if cert.KeyUsage&x509.KeyUsageCRLSign > 0 {
						usages = append(usages, "CRL Sign")
					}
					if cert.KeyUsage&x509.KeyUsageEncipherOnly > 0 {
						usages = append(usages, "Encipher Only")
					}
					if cert.KeyUsage&x509.KeyUsageDecipherOnly > 0 {
						usages = append(usages, "Decipher Only")
					}
					if len(usages) > 0 {
						fmt.Fprintf(buf, "%16s%s", "", usages[0])
						for i := 1; i < len(usages); i++ {
							fmt.Fprintf(buf, ", %s", usages[i])
						}
						fmt.Fprint(buf, "\n")
					} else {
						fmt.Fprintf(buf, "%16sNone\n", "")
					}
				case 17:
					err = printSubjAltNames(ext, cert.DNSNames, cert.EmailAddresses, cert.IPAddresses, cert.URIs, buf)
				case 19:
					// basicConstraints: RFC 5280, 4.2.1.9
					if !cert.BasicConstraintsValid {
						break
					}
					fmt.Fprintf(buf, "%12sX509v3 Basic Constraints:", "")
					if ext.Critical {
						fmt.Fprint(buf, " critical\n")
					} else {
						fmt.Fprint(buf, "\n")
					}
					if cert.IsCA {
						fmt.Fprintf(buf, "%16sCA:TRUE", "")
					} else {
						fmt.Fprintf(buf, "%16sCA:FALSE", "")
					}
					if cert.MaxPathLenZero {
						fmt.Fprint(buf, ", pathlen:0\n")
					} else if cert.MaxPathLen > 0 {
						fmt.Fprintf(buf, ", pathlen:%d\n", cert.MaxPathLen)
					} else {
						fmt.Fprint(buf, "\n")
					}
				case 30:
					// nameConstraints: RFC 5280, 4.2.1.10
					// TODO: Currently crypto/x509 only supports "Permitted" and not "Excluded"
					// subtrees. Furthermore it assumes all types are DNS names which is not
					// necessarily true. This missing functionality should be implemented.
					fmt.Fprintf(buf, "%12sX509v3 Name Constraints:", "")
					if ext.Critical {
						fmt.Fprint(buf, " critical\n")
					} else {
						fmt.Fprint(buf, "\n")
					}
					if len(cert.PermittedDNSDomains) > 0 || len(cert.PermittedEmailAddresses) > 0 || len(cert.PermittedURIDomains) > 0 || len(cert.PermittedIPRanges) > 0 {
						fmt.Fprintf(buf, "%16sPermitted:\n", "")

						if len(cert.PermittedDNSDomains) > 0 {
							fmt.Fprintf(buf, "%18sDNS: %s", "", cert.PermittedDNSDomains[0])
							for i := 1; i < len(cert.PermittedDNSDomains); i++ {
								fmt.Fprintf(buf, ", %s", cert.PermittedDNSDomains[i])
							}
							fmt.Fprint(buf, "\n")
						}
						if len(cert.PermittedEmailAddresses) > 0 {
							fmt.Fprintf(buf, "%18sEmail: %s", "", cert.PermittedEmailAddresses[0])
							for i := 1; i < len(cert.PermittedEmailAddresses); i++ {
								fmt.Fprintf(buf, ", %s", cert.PermittedEmailAddresses[i])
							}
							fmt.Fprint(buf, "\n")
						}
						if len(cert.PermittedURIDomains) > 0 {
							fmt.Fprintf(buf, "%18sURI: %s", "", cert.PermittedURIDomains[0])
							for i := 1; i < len(cert.PermittedURIDomains); i++ {
								fmt.Fprintf(buf, ", %s", cert.PermittedURIDomains[i])
							}
							fmt.Fprint(buf, "\n")
						}
						if len(cert.PermittedIPRanges) > 0 {
							fmt.Fprintf(buf, "%18sIP Range: %s", "", cert.PermittedIPRanges[0])
							for i := 1; i < len(cert.PermittedIPRanges); i++ {
								fmt.Fprintf(buf, ", %s", cert.PermittedIPRanges[i])
							}
							fmt.Fprint(buf, "\n")
						}
					}
					if len(cert.ExcludedDNSDomains) > 0 || len(cert.ExcludedEmailAddresses) > 0 || len(cert.ExcludedURIDomains) > 0 || len(cert.ExcludedIPRanges) > 0 {
						fmt.Fprintf(buf, "%16sExcluded:\n", "")

						if len(cert.ExcludedDNSDomains) > 0 {
							fmt.Fprintf(buf, "%18sDNS: %s", "", cert.ExcludedDNSDomains[0])
							for i := 1; i < len(cert.ExcludedDNSDomains); i++ {
								fmt.Fprintf(buf, ", %s", cert.ExcludedDNSDomains[i])
							}
							fmt.Fprint(buf, "\n")
						}
						if len(cert.ExcludedEmailAddresses) > 0 {
							fmt.Fprintf(buf, "%18sEmail: %s", "", cert.ExcludedEmailAddresses[0])
							for i := 1; i < len(cert.ExcludedEmailAddresses); i++ {
								fmt.Fprintf(buf, ", %s", cert.ExcludedEmailAddresses[i])
							}
							fmt.Fprint(buf, "\n")
						}
						if len(cert.ExcludedURIDomains) > 0 {
							fmt.Fprintf(buf, "%18sURI: %s", "", cert.ExcludedURIDomains[0])
							for i := 1; i < len(cert.ExcludedURIDomains); i++ {
								fmt.Fprintf(buf, ", %s", cert.ExcludedURIDomains[i])
							}
							fmt.Fprint(buf, "\n")
						}
						if len(cert.ExcludedIPRanges) > 0 {
							fmt.Fprintf(buf, "%18sIP Range: %s", "", cert.ExcludedIPRanges[0])
							for i := 1; i < len(cert.ExcludedIPRanges); i++ {
								fmt.Fprintf(buf, ", %s", cert.ExcludedIPRanges[i])
							}
							fmt.Fprint(buf, "\n")
						}
					}

				case 31:
					// CRLDistributionPoints: RFC 5280, 4.2.1.13
					// TODO: Currently crypto/x509 does not fully implement this section,
					// including types and reason flags.
					fmt.Fprintf(buf, "%12sX509v3 CRL Distribution Points:", "")
					if ext.Critical {
						fmt.Fprint(buf, " critical\n")
					} else {
						fmt.Fprint(buf, "\n")
					}
					if len(cert.CRLDistributionPoints) > 0 {
						fmt.Fprintf(buf, "%16sFull Name:\n%18sURI:%s", "", "", cert.CRLDistributionPoints[0])
						for i := 1; i < len(cert.CRLDistributionPoints); i++ {
							fmt.Fprintf(buf, ", URI:%s", cert.CRLDistributionPoints[i])
						}
						fmt.Fprint(buf, "\n")
					}
				case 32:
					// certificatePoliciesExt: RFC 5280, 4.2.1.4
					// TODO: Currently crypto/x509 does not fully impelment this section,
					// including the Certification Practice Statement (CPS)
					fmt.Fprintf(buf, "%12sX509v3 Certificate Policies:", "")
					if ext.Critical {
						fmt.Fprint(buf, " critical\n")
					} else {
						fmt.Fprint(buf, "\n")
					}
					for _, val := range cert.PolicyIdentifiers {
						fmt.Fprintf(buf, "%16sPolicy: %s\n", "", val.String())
					}
				case 35:
					// authorityKeyIdentifier: RFC 5280, 4.2.1.1
					fmt.Fprintf(buf, "%12sX509v3 Authority Key Identifier:", "")
					if ext.Critical {
						fmt.Fprint(buf, " critical\n")
					} else {
						fmt.Fprint(buf, "\n")
					}
					fmt.Fprintf(buf, "%16skeyid", "")
					for _, val := range cert.AuthorityKeyId {
						fmt.Fprintf(buf, ":%02X", val)
					}
					fmt.Fprint(buf, "\n")
				case 37:
					// extKeyUsage: RFC 5280, 4.2.1.12
					fmt.Fprintf(buf, "%12sX509v3 Extended Key Usage:", "")
					if ext.Critical {
						fmt.Fprint(buf, " critical\n")
					} else {
						fmt.Fprint(buf, "\n")
					}
					var list []string
					for _, val := range cert.ExtKeyUsage {
						switch val {
						case x509.ExtKeyUsageAny:
							list = append(list, "Any Usage")
						case x509.ExtKeyUsageServerAuth:
							list = append(list, "Server Authentication")
						case x509.ExtKeyUsageClientAuth:
							list = append(list, "Client Authentication")
						case x509.ExtKeyUsageCodeSigning:
							list = append(list, "Code Signing")
						case x509.ExtKeyUsageEmailProtection:
							list = append(list, "E-mail Protection")
						case x509.ExtKeyUsageIPSECEndSystem:
							list = append(list, "IPSec End System")
						case x509.ExtKeyUsageIPSECTunnel:
							list = append(list, "IPSec Tunnel")
						case x509.ExtKeyUsageIPSECUser:
							list = append(list, "IPSec User")
						case x509.ExtKeyUsageTimeStamping:
							list = append(list, "Time Stamping")
						case x509.ExtKeyUsageOCSPSigning:
							list = append(list, "OCSP Signing")
						default:
							list = append(list, "UNKNOWN")
						}
					}
					for _, oid := range cert.UnknownExtKeyUsage {
						if oid.Equal(oidExtKeyUsageEKCertificate) {
							list = append(list, "EK Certificate")
						} else {
							list = append(list, oid.String())
						}
					}
					if len(list) > 0 {
						fmt.Fprintf(buf, "%16s%s", "", list[0])
						for i := 1; i < len(list); i++ {
							fmt.Fprintf(buf, ", %s", list[i])
						}
						fmt.Fprint(buf, "\n")
					}
				default:
					fmt.Fprintf(buf, "Unknown extension 2.5.29.%d\n", ext.Id[3])
				}
				if err != nil {
					return "", err
				}

				// Continue to next extension
				continue
			}

			switch {
			case ext.Id.Equal(oidExtensionAuthorityInfoAccess):
				// authorityInfoAccess: RFC 5280, 4.2.2.1
				fmt.Fprintf(buf, "%12sAuthority Information Access:", "")
				if ext.Critical {
					fmt.Fprint(buf, " critical\n")
				} else {
					fmt.Fprint(buf, "\n")
				}
				if len(cert.OCSPServer) > 0 {
					fmt.Fprintf(buf, "%16sOCSP - URI:%s", "", cert.OCSPServer[0])
					for i := 1; i < len(cert.OCSPServer); i++ {
						fmt.Fprintf(buf, ",URI:%s", cert.OCSPServer[i])
					}
					fmt.Fprint(buf, "\n")
				}
				if len(cert.IssuingCertificateURL) > 0 {
					fmt.Fprintf(buf, "%16sCA Issuers - URI:%s", "", cert.IssuingCertificateURL[0])
					for i := 1; i < len(cert.IssuingCertificateURL); i++ {
						fmt.Fprintf(buf, ",URI:%s", cert.IssuingCertificateURL[i])
					}
					fmt.Fprint(buf, "\n")
				}
			case ext.Id.Equal(oidNSComment):
				// Netscape comment
				var comment string
				rest, err := asn1.Unmarshal(ext.Value, &comment)
				if err != nil || len(rest) > 0 {
					return "", fmt.Errorf("certinfo: Error parsing OID %q", ext.Id.String())
				}
				if ext.Critical {
					fmt.Fprintf(buf, "%12sNetscape Comment: critical\n%16s%s\n", "", "", comment)
				} else {
					fmt.Fprintf(buf, "%12sNetscape Comment:\n%16s%s\n", "", "", comment)
				}
			case ext.Id.Equal(oidStepProvisioner):
				fmt.Fprintf(buf, "%12sX509v3 Step Provisioner:", "")
				if ext.Critical {
					fmt.Fprint(buf, " critical\n")
				} else {
					fmt.Fprint(buf, "\n")
				}
				val := &stepProvisioner{}
				rest, err := asn1.Unmarshal(ext.Value, val)
				if err != nil || len(rest) > 0 {
					return "", fmt.Errorf("certinfo: Error parsing OID %q", ext.Id.String())
				}

				// Get type name
				var typ string
				if len(stepProvisionerType) > val.Type {
					typ = stepProvisionerType[val.Type]
				} else {
					typ = fmt.Sprintf("%d (unknown)", val.Type)
				}

				fmt.Fprintf(buf, "%16sType: %s\n", "", typ)
				fmt.Fprintf(buf, "%16sName: %s\n", "", string(val.Name))
				if len(val.CredentialID) != 0 {
					fmt.Fprintf(buf, "%16sCredentialID: %s\n", "", string(val.CredentialID))
				}
				var key, value string
				for i, l := 0, len(val.KeyValuePairs); i < l; i += 2 {
					key, value = val.KeyValuePairs[i], "-"
					if i+1 < l {
						value = val.KeyValuePairs[i+1]
					}
					fmt.Fprintf(buf, "%16s%s: %s\n", "", key, value)
				}
			case ext.Id.Equal(oidStepCertificateAuthority):
				fmt.Fprintf(buf, "%12sX509v3 Step Registration Authority:", "")
				if ext.Critical {
					fmt.Fprint(buf, " critical\n")
				} else {
					fmt.Fprint(buf, "\n")
				}
				val := &stepCertificateAuthority{}
				rest, err := asn1.Unmarshal(ext.Value, val)
				if err != nil || len(rest) > 0 {
					return "", fmt.Errorf("certinfo: Error parsing OID %q", ext.Id.String())
				}
				fmt.Fprintf(buf, "%16sType: %s\n", "", val.Type)
				if val.CertificateID != "" {
					fmt.Fprintf(buf, "%16sCertificateID: %s\n", "", val.CertificateID)
				}
				var key, value string
				for i, l := 0, len(val.KeyValuePairs); i < l; i += 2 {
					key, value = val.KeyValuePairs[i], "-"
					if i+1 < l {
						value = val.KeyValuePairs[i+1]
					}
					fmt.Fprintf(buf, "%16s%s: %s\n", "", key, value)
				}
			case ext.Id.Equal(oidStepManagedEndpoint):
				fmt.Fprintf(buf, "%12sX509v3 Step Managed Endpoint:", "")
				if ext.Critical {
					fmt.Fprint(buf, " critical\n")
				} else {
					fmt.Fprint(buf, "\n")
				}
				val := &stepManagedEndpoint{}
				rest, err := asn1.Unmarshal(ext.Value, val)
				if err != nil || len(rest) > 0 {
					return "", fmt.Errorf("certinfo: Error parsing OID %q", ext.Id.String())
				}

				// Get kind name
				var kind string
				if len(stepManagedEndpointKind) > val.Kind {
					kind = stepManagedEndpointKind[val.Kind]
				} else {
					kind = fmt.Sprintf("%d (unknown)", val.Kind)
				}

				fmt.Fprintf(buf, "%16sKind: %s\n", "", kind)
				fmt.Fprintf(buf, "%16sEndpointID: %s\n", "", val.EndpointID)
			case ext.Id.Equal(oidSignedCertificateTimestampList):
				fmt.Fprintf(buf, "%12sRFC6962 Certificate Transparency SCT:", "")
				if ext.Critical {
					fmt.Fprint(buf, " critical\n")
				} else {
					fmt.Fprint(buf, "\n")
				}
				var raw []byte
				rest, err := asn1.Unmarshal(ext.Value, &raw)
				if err != nil || len(rest) > 0 {
					return "", fmt.Errorf("certinfo: Error parsing OID %q", ext.Id.String())
				}
				var sctList ctx509.SignedCertificateTimestampList
				if rest, err := cttls.Unmarshal(raw, &sctList); err != nil || len(rest) > 0 {
					return "", fmt.Errorf("certinfo: Error parsing OID %q", ext.Id.String())
				}
				scts, err := ctutil.ParseSCTsFromSCTList(&sctList)
				if err != nil {
					return "", fmt.Errorf("certinfo: Error parsing OID %q", ext.Id.String())
				}

				for i, sct := range scts {
					sec := int64(sct.Timestamp / 1000)
					nsec := int64(sct.Timestamp % 1000)
					fmt.Fprintf(buf, "%16sSCT [%d]:\n", "", i)
					fmt.Fprintf(buf, "%20sVersion: %s (%#x)\n", "", sct.SCTVersion, int64(sct.SCTVersion))
					fmt.Fprintf(buf, "%20sLogID: %s\n", "", toBase64(sct.LogID.KeyID[:]))
					fmt.Fprintf(buf, "%20sTimestamp: %s\n", "", time.Unix(sec, nsec*1e6).UTC().Format(sctTimeFormat))
					// There are no available extensions
					// fmt.Fprintf(buf, "%20sExtensions: %v\n", "", sct.Extensions)
					printSCTSignature(sct.Signature, buf)
				}
			case ext.Id.Equal(oidYubicoFirmwareVersion):
				printExtensionHeader("X509v3 YubiKey Firmware Version", ext, buf)
				fmt.Fprintf(buf, "%16s%s\n", "", yubicoVersion(ext.Value))
			case ext.Id.Equal(oidYubicoSerialNumber):
				var serialNumber int
				rest, err := asn1.Unmarshal(ext.Value, &serialNumber)
				if err != nil || len(rest) > 0 {
					return "", fmt.Errorf("certinfo: Error parsing OID %q", ext.Id.String())
				}
				printExtensionHeader("X509v3 YubiKey Serial Number", ext, buf)
				fmt.Fprintf(buf, "%16s%d\n", "", serialNumber)
			case ext.Id.Equal(oidYubicoPolicy):
				policies := yubicoPolicies(ext.Value)
				printExtensionHeader("X509v3 YubiKey Policy", ext, buf)
				for _, p := range policies {
					fmt.Fprintf(buf, "%16s%s\n", "", p)
				}
			case ext.Id.Equal(oidYubicoFormfactor):
				printExtensionHeader("X509v3 YubiKey Formfactor", ext, buf)
				fmt.Fprintf(buf, "%16s%s\n", "", yubicoFormfactor(ext.Value))
			case ext.Id.Equal(oidYubicoFipsCertified):
				printExtensionHeader("X509v3 YubiKey Certification", ext, buf)
				fmt.Fprintf(buf, "%16sFIPS Certified\n", "")
			case ext.Id.Equal(oidYubicoCspnCertified):
				printExtensionHeader("X509v3 YubiKey Certification", ext, buf)
				fmt.Fprintf(buf, "%16sCSPN Certified\n", "")
			case ext.Id.Equal(oidSigstoreOIDCIssuer):
				printExtensionHeader("Sigstore OIDC Issuer", ext, buf)
				fmt.Fprintf(buf, "%16s%s\n", "", string(ext.Value))
			case ext.Id.Equal(oidSigstoreGithubWorkflowTrigger):
				printExtensionHeader("Sigstore GitHub Workflow Trigger", ext, buf)
				fmt.Fprintf(buf, "%16s%s\n", "", string(ext.Value))
			case ext.Id.Equal(oidSigstoreGithubWorkflowSha):
				printExtensionHeader("Sigstore GitHub Workflow SHA Hash", ext, buf)
				fmt.Fprintf(buf, "%16s%s\n", "", string(ext.Value))
			case ext.Id.Equal(oidSigstoreGithubWorkflowName):
				printExtensionHeader("Sigstore GitHub Workflow Name", ext, buf)
				fmt.Fprintf(buf, "%16s%s\n", "", string(ext.Value))
			case ext.Id.Equal(oidSigstoreGithubWorkflowRepository):
				printExtensionHeader("Sigstore GitHub Workflow Repository", ext, buf)
				fmt.Fprintf(buf, "%16s%s\n", "", string(ext.Value))
			case ext.Id.Equal(oidSigstoreGithubWorkflowRef):
				printExtensionHeader("Sigstore GitHub Workflow Ref", ext, buf)
				fmt.Fprintf(buf, "%16s%s\n", "", string(ext.Value))
			default:
				fmt.Fprintf(buf, "%12s%s:", "", ext.Id.String())
				if ext.Critical {
					fmt.Fprint(buf, " critical\n")
				} else {
					fmt.Fprint(buf, "\n")
				}
				value := bytes.Runes(ext.Value)
				sanitized := make([]rune, len(value))
				for i, r := range value {
					if strconv.IsPrint(r) && r != '�' {
						sanitized[i] = r
					} else {
						sanitized[i] = '.'
					}
				}
				fmt.Fprintf(buf, "%16s%s\n", "", string(sanitized))
			}
		}
	}

	// Signature
	printSignature(cert.SignatureAlgorithm, cert.Signature, buf)

	// Optional: Print the full PEM certificate
	/*
		pemBlock := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		buf.Write(pem.EncodeToMemory(&pemBlock))
	*/

	return buf.String(), nil
}

var (
	oidExtSubjectKeyID     = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtNameConstraints  = asn1.ObjectIdentifier{2, 5, 29, 30}
)

// RFC 5280, 4.2.1.9
type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// RFC 5280, 4.2.1.10
type nameConstraints struct {
	Permitted []generalSubtree `asn1:"optional,tag:0"`
	Excluded  []generalSubtree `asn1:"optional,tag:1"`
}

type generalSubtree struct {
	Name string `asn1:"tag:2,optional,ia5"`
}

// RFC 5280, 4.2.1.3
func parseKeyUsage(val []byte) (x509.KeyUsage, error) {
	var usageBits asn1.BitString
	if _, err := asn1.Unmarshal(val, &usageBits); err != nil {
		return 0, err
	}
	var usage int
	for i := 0; i < 9; i++ {
		if usageBits.At(i) != 0 {
			usage |= 1 << uint(i)
		}
	}
	return x509.KeyUsage(usage), nil
}

// RFC 5280, 4.2.1.12  Extended Key Usage
//
// anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }
//
// id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }
//
// id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
// id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
// id-kp-codeSigning            OBJECT IDENTIFIER ::= { id-kp 3 }
// id-kp-emailProtection        OBJECT IDENTIFIER ::= { id-kp 4 }
// id-kp-timeStamping           OBJECT IDENTIFIER ::= { id-kp 8 }
// id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
var (
	oidExtKeyUsageAny                            = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidExtKeyUsageServerAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageCodeSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidExtKeyUsageEmailProtection                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidExtKeyUsageIPSECEndSystem                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidExtKeyUsageIPSECTunnel                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidExtKeyUsageIPSECUser                      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidExtKeyUsageTimeStamping                   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsageOCSPSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidExtKeyUsageMicrosoftServerGatedCrypto     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	oidExtKeyUsageNetscapeServerGatedCrypto      = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
	oidExtKeyUsageMicrosoftCommercialCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}
	oidExtKeyUsageMicrosoftKernelCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
	oidExtKeyUsageEKCertificate                  = asn1.ObjectIdentifier{2, 23, 133, 8, 1}
)

// CertificateRequestText returns a human-readable string representation
// of the certificate request csr. The format is similar (but not identical)
// to the OpenSSL way of printing certificates.
func CertificateRequestText(csr *x509.CertificateRequest) (string, error) {
	var bbuf bytes.Buffer
	bbuf.Grow(4096) // 4KiB should be enough
	buf := &bbuf

	fmt.Fprint(buf, "Certificate Request:\n")
	fmt.Fprintf(buf, "%4sData:\n", "")
	printVersion(csr.Version, buf)

	// Subject information
	err := printSubjectInformation(&csr.Subject, csr.PublicKeyAlgorithm, csr.PublicKey, buf)
	if err != nil {
		return "", err
	}

	// Optional extensions for PKCS #10, RFC 2986
	if csr.Version == 0 && len(csr.Extensions) > 0 {
		fmt.Fprintf(buf, "%8sRequested Extensions:\n", "")
		unknownExts := []pkix.Extension{}
		for _, ext := range csr.Extensions {
			switch {
			case ext.Id.Equal(oidExtSubjectKeyID):
				err = printSubjKeyID(ext, buf)
			case ext.Id.Equal(oidExtSubjectAltName):
				err = printSubjAltNames(ext, csr.DNSNames, csr.EmailAddresses, csr.IPAddresses, csr.URIs, buf)
			case ext.Id.Equal(oidExtKeyUsage):
				// keyUsage: RFC 5280, 4.2.1.3
				ku, err := parseKeyUsage(ext.Value)
				if err != nil {
					fmt.Fprintf(buf, "%12sX509v3 Key Usage: failed to decode\n", "")
					continue
				}
				fmt.Fprintf(buf, "%12sX509v3 Key Usage:", "")
				if ext.Critical {
					fmt.Fprint(buf, " critical\n")
				} else {
					fmt.Fprint(buf, "\n")
				}
				kus := []struct {
					ku   x509.KeyUsage
					desc string
				}{
					{x509.KeyUsageDigitalSignature, "Digital Signature"},
					{x509.KeyUsageContentCommitment, "Content Commitment"},
					{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
					{x509.KeyUsageDataEncipherment, "Data Encipherment"},
					{x509.KeyUsageKeyAgreement, "Key Agreement"},
					{x509.KeyUsageCertSign, "Certificate Sign"},
					{x509.KeyUsageCRLSign, "CRL Sign"},
					{x509.KeyUsageEncipherOnly, "Encipher Only"},
					{x509.KeyUsageDecipherOnly, "Decipher Only"},
				}
				var usages []string
				for _, u := range kus {
					if ku&u.ku > 0 {
						usages = append(usages, u.desc)
					}
				}
				if len(usages) > 0 {
					fmt.Fprintf(buf, "%16s%s", "", usages[0])
					for i := 1; i < len(usages); i++ {
						fmt.Fprintf(buf, ", %s", usages[i])
					}
					fmt.Fprint(buf, "\n")
				} else {
					fmt.Fprintf(buf, "%16sNone\n", "")
				}
			case ext.Id.Equal(oidExtBasicConstraints):
				// basicConstraints: RFC 5280, 4.2.1.9
				var constraints basicConstraints
				_, err := asn1.Unmarshal(ext.Value, &constraints)
				if err != nil {
					fmt.Fprintf(buf, "%12sX509v3 Basic Constraints: failed to decode\n", "")
					continue
				}
				fmt.Fprintf(buf, "%12sX509v3 Basic Constraints:", "")
				if ext.Critical {
					fmt.Fprint(buf, " critical\n")
				} else {
					fmt.Fprint(buf, "\n")
				}
				if constraints.IsCA {
					fmt.Fprintf(buf, "%16sCA:TRUE", "")
				} else {
					fmt.Fprintf(buf, "%16sCA:FALSE", "")
				}
				switch {
				case constraints.MaxPathLen == 0:
					fmt.Fprint(buf, ", pathlen:0\n")
				case constraints.MaxPathLen > 0:
					fmt.Fprintf(buf, ", pathlen:%d\n", constraints.MaxPathLen)
				default:
					fmt.Fprint(buf, "\n")
				}
			case ext.Id.Equal(oidExtNameConstraints):
				// RFC 5280, 4.2.1.10
				// NameConstraints ::= SEQUENCE {
				//      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
				//      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
				//
				// GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
				//
				// GeneralSubtree ::= SEQUENCE {
				//      base                    GeneralName,
				//      minimum         [0]     BaseDistance DEFAULT 0,
				//      maximum         [1]     BaseDistance OPTIONAL }
				//
				// BaseDistance ::= INTEGER (0..MAX)
				var constraints nameConstraints
				_, err := asn1.Unmarshal(ext.Value, &constraints)
				if err != nil {
					fmt.Fprintf(buf, "%12sX509v3 Name Constraints: failed to decode\n", "")
					continue
				}
				if len(constraints.Excluded) > 0 && ext.Critical {
					fmt.Fprintf(buf, "%12sX509v3 Name Constraints: failed to decode: unexpected excluded name constraints\n", "")
					continue
				}
				var permittedDNSDomains []string
				for _, subtree := range constraints.Permitted {
					if subtree.Name == "" {
						continue
					}
					permittedDNSDomains = append(permittedDNSDomains, subtree.Name)
				}
				fmt.Fprintf(buf, "%12sX509v3 Name Constraints:", "")
				if ext.Critical {
					fmt.Fprint(buf, " critical\n")
				} else {
					fmt.Fprint(buf, "\n")
				}
				if len(permittedDNSDomains) > 0 {
					fmt.Fprintf(buf, "%16sPermitted:\n%18s%s", "", "", permittedDNSDomains[0])
					for i := 1; i < len(permittedDNSDomains); i++ {
						fmt.Fprintf(buf, ", %s", permittedDNSDomains[i])
					}
					fmt.Fprint(buf, "\n")
				}
			case ext.Id.Equal(oidExtExtendedKeyUsage):
				// extKeyUsage: RFC 5280, 4.2.1.12
				// id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }
				//
				// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
				//
				// KeyPurposeId ::= OBJECT IDENTIFIER
				var keyUsage []asn1.ObjectIdentifier
				if _, err = asn1.Unmarshal(ext.Value, &keyUsage); err != nil {
					fmt.Fprintf(buf, "%12sX509v3 Extended Key Usage: failed to decode\n", "")
					continue
				}
				ekus := []struct {
					oid  asn1.ObjectIdentifier
					desc string
				}{
					{oidExtKeyUsageAny, "Any Usage"},
					{oidExtKeyUsageServerAuth, "Server Authentication"},
					{oidExtKeyUsageClientAuth, "Client Authentication"},
					{oidExtKeyUsageCodeSigning, "Code Signing"},
					{oidExtKeyUsageEmailProtection, "E-mail Protection"},
					{oidExtKeyUsageIPSECEndSystem, "IPSec End System"},
					{oidExtKeyUsageIPSECTunnel, "IPSec Tunnel"},
					{oidExtKeyUsageIPSECUser, "IPSec User"},
					{oidExtKeyUsageTimeStamping, "Time Stamping"},
					{oidExtKeyUsageOCSPSigning, "OCSP Signing"},
					{oidExtKeyUsageMicrosoftServerGatedCrypto, "Microsoft Server Gated Crypto"},
					{oidExtKeyUsageNetscapeServerGatedCrypto, "Netscape Server Gated Crypto"},
					{oidExtKeyUsageMicrosoftCommercialCodeSigning, "Microsoft Commercial Code Signing"},
					{oidExtKeyUsageMicrosoftKernelCodeSigning, "Microsoft Kernel Code Signing"},
					{oidExtKeyUsageEKCertificate, "EK Certificate"},
				}
				var list []string
				for _, u := range keyUsage {
					found := false
					for _, eku := range ekus {
						if u.Equal(eku.oid) {
							list = append(list, eku.desc)
							found = true
						}
					}
					if !found {
						list = append(list, fmt.Sprintf("UNKNOWN(%s)", u.String()))
					}
				}
				fmt.Fprintf(buf, "%12sX509v3 Extended Key Usage:", "")
				if ext.Critical {
					fmt.Fprint(buf, " critical\n")
				} else {
					fmt.Fprint(buf, "\n")
				}
				if len(list) > 0 {
					fmt.Fprintf(buf, "%16s%s", "", list[0])
					for i := 1; i < len(list); i++ {
						fmt.Fprintf(buf, ", %s", list[i])
					}
					fmt.Fprint(buf, "\n")
				}
			default:
				unknownExts = append(unknownExts, ext)
			}
			if err != nil {
				return "", err
			}
		}
		if len(unknownExts) > 0 {
			fmt.Fprintf(buf, "%8sAttributes:\n", "")
			for _, ext := range unknownExts {
				fmt.Fprintf(buf, "%12s%s:", "", ext.Id.String())
				if ext.Critical {
					fmt.Fprint(buf, " critical\n")
				} else {
					fmt.Fprint(buf, "\n")
				}
				value := bytes.Runes(ext.Value)
				sanitized := make([]rune, len(value))
				hasSpecialChar := false
				for i, r := range value {
					if strconv.IsPrint(r) && r != '�' {
						sanitized[i] = r
					} else {
						hasSpecialChar = true
						sanitized[i] = '.'
					}
				}
				fmt.Fprintf(buf, "%16s%s\n", "", string(sanitized))
				if hasSpecialChar {
					fmt.Fprintf(buf, "%16s", "")
					for i, b := range ext.Value {
						fmt.Fprintf(buf, "%02x", b)
						if i != len(ext.Value)-1 {
							fmt.Fprint(buf, ":")
						}
					}
					fmt.Fprint(buf, "\n")
				}
			}
		}
	}

	// Signature
	printSignature(csr.SignatureAlgorithm, csr.Signature, buf)

	return buf.String(), nil
}
