package ca

import "crypto/x509"

type Secrets interface {
	GetCACert() (*x509.Certificate, error)
}
