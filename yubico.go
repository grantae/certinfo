package certinfo

import (
	"encoding/asn1"
	"fmt"
	"strconv"
)

// Yubico PIV attestation OIDs from
// https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
var (
	// Firmware version, encoded as 3 bytes, like: 040300 for 4.3.0
	oidYubicoFirmwareVersion = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 3}
	// Serial number of the YubiKey, encoded as an integer.
	oidYubicoSerialNumber = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}
	// Two bytes, the first encoding pin policy and the second touch policy:
	//
	//   - Pin policy: 01 - never, 02 - once per session, 03 - always
	//   - Touch policy: 01 - never, 02 - always, 03 - cached for 15s
	oidYubicoPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8}
	// Formfactor, encoded as one byte:
	//
	//   - USB-A Keychain: 01 (81 for FIPS Devices)
	//   - USB-A Nano: 02 (82 for FIPS Devices)
	//   - USB-C Keychain: 03 (83 for FIPS Devices)
	//   - USB-C Nano: 04 (84 for FIPS Devices)
	//   - Lightning and USB-C: 05 (85 for FIPS Devices)
	oidYubicoFormfactor = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 9}
	// FIPS Certified YubiKey.
	oidYubicoFipsCertified = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 10}
	// CSPN Certified YubiKey.
	oidYubicoCspnCertified = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 11}
)

func yubicoVersion(v []byte) string {
	if len(v) == 0 {
		return "unknown"
	}

	var version string
	for i, b := range v {
		if i < len(v)-1 {
			version += strconv.Itoa(int(b)) + "."
		} else {
			version += strconv.Itoa(int(b))
		}
	}
	return version
}

func yubicoPolicies(v []byte) []string {
	if len(v) == 0 {
		return []string{"unknown"}
	}
	policies := make([]string, 0, 2)
	for i, b := range v {
		switch i {
		case 0:
			switch b {
			case 1:
				policies = append(policies, "PIN policy: never")
			case 2:
				policies = append(policies, "PIN policy: once per session")
			case 3:
				policies = append(policies, "PIN policy: always")
			default:
				policies = append(policies, fmt.Sprintf("PIN policy: unknown (0x%02x)", b))
			}
		case 1:
			switch b {
			case 1:
				policies = append(policies, "Touch policy: never")
			case 2:
				policies = append(policies, "Touch policy: always")
			case 3:
				policies = append(policies, "Touch policy: once per session")
			default:
				policies = append(policies, fmt.Sprintf("Touch policy: unknown (0x%02x)", b))
			}
		default:
			return policies
		}
	}
	return policies
}

func yubicoFormfactor(v []byte) (s string) {
	if len(v) == 0 {
		return "unknown"
	}
	switch v[0] {
	case 1, 81:
		s = "USB-A Keychain"
	case 2, 82:
		s = "USB-A Nano"
	case 3, 83:
		s = "USB-C Keychain"
	case 4, 84:
		s = "USB-C Nano"
	case 5, 85:
		s = "Lightning or USB-C"
	default:
		return fmt.Sprintf("unknown (0x%02x)", v[0])
	}
	if v[0] > 80 {
		s += " (FIPS)"
	}
	return
}
