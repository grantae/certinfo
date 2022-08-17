package certinfo

import (
	"crypto/x509/pkix"
	"encoding/asn1"
)

// Option provides configurable options to output formatting.
type Option func(*options)

type options struct {
	// formatters maps oid -> format funcs
	formatters map[string]Formatter
}

// WithFormatter configures a custom formatting function for the given OID.
func WithFormatter(oid asn1.ObjectIdentifier, fn Formatter) Option {
	return func(opts *options) {
		opts.formatters[oid.String()] = fn
	}
}

// Formatter returns a formatted string for a given pkix.Extension.
// Formatters should return relative strings - padding will be prepended
// automatically when the certificate is printed.
type Formatter func(ext pkix.Extension) string
