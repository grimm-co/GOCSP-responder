package relational

import (
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/lamassuiot/GOCSP-responder/pkg/depot"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	_ "github.com/lib/pq"
)

type relationalDB struct {
	db     *sql.DB
	logger log.Logger
}

func NewDB(driverName string, dataSourceName string, logger log.Logger) (depot.Depot, error) {
	db, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		return nil, err
	}
	err = checkDBAlive(db)
	for err != nil {
		level.Warn(logger).Log("msg", "Trying to connect to signed certificates database")
		err = checkDBAlive(db)
	}

	return &relationalDB{db: db, logger: logger}, nil
}

func checkDBAlive(db *sql.DB) error {
	sqlStatement := `
	SELECT WHERE 1=0`
	_, err := db.Query(sqlStatement)
	return err
}

func (r *relationalDB) GetIndexEntry(serial *big.Int) (*depot.IndexEntry, error) {
	var t string = "060102150405Z"
	serialString := fmt.Sprintf("%x", serial)

	sqlStatement := `
	SELECT *
	FROM ca_store
	WHERE serial = $1;
	`
	row := r.db.QueryRow(sqlStatement, serialString)

	var unparsedIE struct {
		Id                int
		Status            string
		Serial            string
		IssueTime         string
		RevocationTime    string
		DistinguishedName string
		CertPath          string
	}

	err := row.Scan(&unparsedIE.Id, &unparsedIE.Status, &unparsedIE.IssueTime, &unparsedIE.RevocationTime, &unparsedIE.Serial, &unparsedIE.DistinguishedName, &unparsedIE.CertPath)
	if err != nil {
		err = fmt.Errorf("Serial 0x%x not found", serial)
		level.Error(r.logger).Log("err", err, "msg", "Could not find serial "+serialString+" in signed certificates database")
		return nil, err
	}
	level.Info(r.logger).Log("msg", "Index Entry with serial "+serialString+" found")

	var ie depot.IndexEntry
	ie.Status = []byte(unparsedIE.Status)[0]
	ie.Serial, _ = new(big.Int).SetString(unparsedIE.Serial, 16)
	ie.IssueTime, _ = time.Parse(t, unparsedIE.IssueTime)

	if ie.Status == depot.StatusValid {
		level.Info(r.logger).Log("msg", "Serial "+serialString+" Index entry status is valid")
		ie.RevocationTime = time.Time{}
	} else if ie.Status == depot.StatusRevoked {
		level.Info(r.logger).Log("msg", "Serial "+serialString+" Index Entry status is revoked")
		ie.RevocationTime, _ = time.Parse(t, unparsedIE.RevocationTime)
	}

	ie.DistinguishedName = unparsedIE.DistinguishedName

	return &ie, nil

}

func (r *relationalDB) InsertCertificate(ie *depot.IndexEntry) error {
	sqlStatement := `
	INSERT INTO ca_store(id, status, expirationDate, revocationDate, serial, dn, certpath)
	VALUES($1, $2, $3, $4, $5, $6, $7)
	RETURNING serial;
	`

	serialHex := fmt.Sprintf("%x", ie.Serial)
	var serial string
	var t string = "060102150405Z"

	err := r.db.QueryRow(sqlStatement, ie.Id, string(ie.Status), ie.IssueTime.Format(t), ie.RevocationTime.Format(t), serialHex, ie.DistinguishedName, ie.CertPath).Scan(&serial)
	if err != nil {
		level.Error(r.logger).Log("err", err, "msg", "Could not insert Index Entry with serial "+serialHex+" in signed certificates database")
		return err
	}
	level.Info(r.logger).Log("msg", "Index Entry with serial "+serialHex+" inserted in signed certificates database")
	return nil
}

func (r *relationalDB) RevokeCertificate(ie *depot.IndexEntry) error {
	serialHex := fmt.Sprintf("%x", ie.Serial)
	var t string = "060102150405Z"

	sqlStatement := `
	UPDATE ca_store
	SET status = 'R', revocationDate = $1
	WHERE dn = $2 AND serial = $3;
	`

	res, err := r.db.Exec(sqlStatement, time.Now().Format(t), ie.DistinguishedName, serialHex)
	if err != nil {
		level.Error(r.logger).Log("err", err, "msg", "Could not revoke certificate with serial "+serialHex+" in signed certificates database")
		return err
	}

	count, err := res.RowsAffected()
	if err != nil {
		level.Error(r.logger).Log("err", err, "msg", "Could not revoke certificate with serial "+serialHex+" in signed certificates database")
		return err
	}

	if count <= 0 {
		err = errors.New("No rows have been updated in database")
		level.Error(r.logger).Log("err", err)
		return err
	}
	level.Info(r.logger).Log("msg", "Certificate with serial "+serialHex+" revoked in signed certificates database")
	return nil
}

func (r *relationalDB) DeleteCertificate(ie *depot.IndexEntry) error {
	serialHex := fmt.Sprintf("%x", ie.Serial)

	sqlStatement := `
	DELETE FROM ca_store
	WHERE dn = $1 AND serial = $2; 
	`

	res, err := r.db.Exec(sqlStatement, ie.DistinguishedName, serialHex)
	if err != nil {
		level.Error(r.logger).Log("err", err, "Could not delete certificate with serial "+serialHex+" from signed certificates database")
		return err
	}

	count, err := res.RowsAffected()
	if err != nil {
		level.Error(r.logger).Log("err", err, "Could not delete certificate with serial "+serialHex+" from signed certificates database")
		return err
	}

	if count <= 0 {
		err = errors.New("No rows have been updated in database")
		level.Error(r.logger).Log("err", err)
		return errors.New("No rows updated")
	}
	level.Info(r.logger).Log("msg", "Certificate with serial "+serialHex+" deleted from signed certificates database")
	return nil

}
