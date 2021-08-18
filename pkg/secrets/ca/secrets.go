package secrets

import (
	"crypto/x509"
	"math/big"
)

type Cert struct {
	Status         rune
	SerialNumber   string
	CaName         string
	CN             string
	PublicKey      string
	CRT            x509.Certificate
	ValidFrom      string
	ValidTo        string
	RevocationTime int64
}

type Secrets interface {
	GetCAs() ([]Cert, error)
	GetCACert(caName string) (Cert, error)
	GetCert(caName string, serialNumber string) (Cert, error)
	GetCertBigInt(caName string, serialNumber *big.Int) (Cert, error)
}

const (
	StatusValid   = 'V'
	StatusRevoked = 'R'
	StatusExpired = 'E'
)
