package depot

import (
	"math/big"
	"time"
)

type IndexEntry struct {
	Id                int
	Status            byte
	Serial            *big.Int
	IssueTime         time.Time
	RevocationTime    time.Time
	DistinguishedName string
	CertPath          string
}

// I only know of two types, but more can be added later
const (
	StatusValid   = 'V'
	StatusRevoked = 'R'
	StatusExpired = 'E'
)

type Depot interface {
	GetIndexEntry(serial *big.Int) (*IndexEntry, error)
	InsertCertificate(ie *IndexEntry) error
	RevokeCertificate(ie *IndexEntry) error
	DeleteCertificate(ie *IndexEntry) error
}
