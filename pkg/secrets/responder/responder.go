package responder

import (
	"crypto"
	"crypto/x509"
)

type Secrets interface {
	GetResponderKey() (crypto.PrivateKey, error)
	GetResponderCert() (*x509.Certificate, error)
	GetResponderCertFile() string
	GetResponderKeyFile() string
}
