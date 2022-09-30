# Certificate Information for Go

A Golang tool for printing x509 TLS certificates in a format similar to OpenSSL.

This is a (maintained) fork of [grantae/certinfo](https://github.com/grantae/certinfo).

In addition to being able to extract and print standard information from any x509 certificate (request), it also includes capabilities to extract and print properties specific to the [Smallstep toolchain](https://github.com/smallstep) and other, selected OIDs.

## Installation

```console
go get github.com/smallstep/certinfo
```

## Usage

### Print a certificate from a website

```go
package main

import (
  "crypto/tls"
  "fmt"
  "log"

  "github.com/smallstep/certinfo"
)

func main() {
  // Connect to google.com
  cfg := tls.Config{}
  conn, err := tls.Dial("tcp", "google.com:443", &cfg)
  if err != nil {
    log.Fatalln("TLS connection failed: " + err.Error())
  }
  // Grab the last certificate in the chain
  certChain := conn.ConnectionState().PeerCertificates
  cert := certChain[len(certChain)-1]

  // Print the certificate
  result, err := certinfo.CertificateText(cert)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Print(result)
}
```

### Print a PEM-encoded certificate from a file

```go
package main

import (
  "crypto/x509"
  "encoding/pem"
  "fmt"
  "io/ioutil"
  "log"

  "github.com/smallstep/certinfo"
)

func main() {
  // Read and parse the PEM certificate file
  pemData, err := ioutil.ReadFile("cert.pem")
  if err != nil {
    log.Fatal(err)
  }
  block, rest := pem.Decode([]byte(pemData))
  if block == nil || len(rest) > 0 {
    log.Fatal("Certificate decoding error")
  }
  cert, err := x509.ParseCertificate(block.Bytes)
  if err != nil {
    log.Fatal(err)
  }

  // Print the certificate
  result, err := certinfo.CertificateText(cert)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Print(result)
}
```

## Testing

```console
go test github.com/smallstep/certinfo
```

This compares several PEM-encoded certificates with their expected outputs.

## License

MIT -- see `LICENSE` for more information.
