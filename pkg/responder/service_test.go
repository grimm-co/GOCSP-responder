package responder

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/lamassuiot/GOCSP-responder/pkg/crypto/ocsp"
	"github.com/lamassuiot/GOCSP-responder/pkg/depot"
	"github.com/lamassuiot/GOCSP-responder/pkg/depot/relational"
	"github.com/lamassuiot/GOCSP-responder/pkg/secrets/ca"
	"github.com/lamassuiot/GOCSP-responder/pkg/secrets/responder"
	"github.com/lamassuiot/GOCSP-responder/pkg/secrets/responder/file"

	cafile "github.com/lamassuiot/GOCSP-responder/pkg/secrets/ca/file"

	"github.com/go-kit/kit/log"
)

type serviceSetUp struct {
	caSecrets   ca.Secrets
	respSecrets responder.Secrets
	depot       depot.Depot
}

var flFileCA = flag.String("fileca", envString("RESPONDER_FILE_CA", ""), "File CA")
var flResponderKey = flag.String("key", envString("RESPONDER_KEY", ""), "responder key")
var flResponderCert = flag.String("cert", envString("RESPONDER_CERT", ""), "responder certificate")
var flDepotDBName = flag.String("dbname", envString("RESPONDER_DB_NAME", "ca_store"), "DB name")
var flDepotDBUser = flag.String("dbuser", envString("RESPONDER_DB_USER", ""), "DB username")
var flDepotPassword = flag.String("dbpassword", envString("RESPONDER_DB_PASSWORD", ""), "DB password")
var flDepotHost = flag.String("dbhost", envString("RESPONDER_DB_HOST", ""), "DB host")
var flDepotPort = flag.String("dbport", envString("RESPONDER_DB_PORT", ""), "DB port")

func TestVerify(t *testing.T) {
	stu := setup(t)
	srv, err := NewService(stu.caSecrets, stu.respSecrets, stu.depot)
	if err != nil {
		t.Fatal("Unable to create service")
	}
	ctx := context.Background()

	issuerCert := readCertificate(t, "../../ca/enroller.crt")

	unknownCert := readCertificate(t, "testdata/unknown.crt")
	unknownReq, err := ocsp.CreateRequest(unknownCert, issuerCert, &ocsp.RequestOptions{})
	if err != nil {
		t.Fatal("Unable to build unknown certificate OCSP request")
	}

	validCert := readCertificate(t, "testdata/valid.crt")
	stu.insertCertificate(t, validCert)
	validReq, err := ocsp.CreateRequest(validCert, issuerCert, &ocsp.RequestOptions{})
	if err != nil {
		t.Fatal("Unable to build valid certificate OCSP request")
	}

	revokedCert := readCertificate(t, "testdata/revoked.crt")
	stu.insertCertificate(t, revokedCert)
	stu.revokeCertificate(t, revokedCert)
	revokedReq, err := ocsp.CreateRequest(revokedCert, issuerCert, &ocsp.RequestOptions{})
	if err != nil {
		t.Fatal("Unable to build revoked certificate OCSP request")
	}

	testCases := []struct {
		name    string
		request []byte
		status  int
	}{
		{"Unknown certificate", unknownReq, ocsp.Unknown},
		{"Good certificate", validReq, ocsp.Good},
		{"Revoked certificate", revokedReq, ocsp.Revoked},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Testing %s", tc.name), func(t *testing.T) {
			resp, err := srv.Verify(ctx, tc.request)
			if err != nil {
				t.Errorf("Service returned unexpected error: %s", err)
			}
			ocspResp, err := ocsp.ParseResponse(resp, issuerCert)
			if err != nil {
				t.Errorf("Unable to parse certificate response")
			}
			if ocspResp.Status != tc.status {
				t.Errorf("Got result is %d; want %d", ocspResp.Status, tc.status)
			}
		})
	}

	stu.deleteCertificate(t, validCert)
	stu.deleteCertificate(t, revokedCert)
}

func setup(t *testing.T) *serviceSetUp {
	t.Helper()
	buf := &bytes.Buffer{}
	logger := log.NewJSONLogger(buf)

	caSecrets := cafile.NewFile(*flFileCA, logger)
	respSecrets := file.NewFile(*flResponderKey, *flResponderCert, logger)

	dataSourceName := "dbname=" + *flDepotDBName + " user=" + *flDepotDBUser + " password=" + *flDepotPassword + " host=" + *flDepotHost + " port=" + *flDepotPort + " sslmode=disable"
	depot, err := relational.NewDB("postgres", dataSourceName, logger)
	if err != nil {
		t.Fatal("Unable to connect with depot DB")
	}

	return &serviceSetUp{
		caSecrets:   caSecrets,
		respSecrets: respSecrets,
		depot:       depot,
	}
}

func (stu *serviceSetUp) insertCertificate(t *testing.T, cert *x509.Certificate) {
	t.Helper()

	ie := &depot.IndexEntry{
		Id:                1,
		Status:            []byte("V")[0],
		DistinguishedName: makeDn(t, cert),
		IssueTime:         cert.NotAfter,
		RevocationTime:    time.Time{},
		Serial:            cert.SerialNumber,
		CertPath:          "/tmp",
	}
	err := stu.depot.InsertCertificate(ie)
	if err != nil {
		t.Fatal("Unable to insert certificate in depot")
	}
}

func (stu *serviceSetUp) revokeCertificate(t *testing.T, cert *x509.Certificate) {
	t.Helper()

	ie := &depot.IndexEntry{
		Id:                1,
		Status:            []byte("R")[0],
		DistinguishedName: makeDn(t, cert),
		IssueTime:         cert.NotAfter,
		RevocationTime:    time.Time{},
		Serial:            cert.SerialNumber,
		CertPath:          "/tmp",
	}
	err := stu.depot.RevokeCertificate(ie)
	if err != nil {
		t.Fatal("Unable to revoke certificate in depot")
	}
}

func (stu *serviceSetUp) deleteCertificate(t *testing.T, cert *x509.Certificate) {
	t.Helper()

	ie := &depot.IndexEntry{
		Id:                1,
		Status:            []byte("V")[0],
		DistinguishedName: makeDn(t, cert),
		IssueTime:         cert.NotAfter,
		RevocationTime:    time.Time{},
		Serial:            cert.SerialNumber,
		CertPath:          "/tmp",
	}
	err := stu.depot.DeleteCertificate(ie)
	if err != nil {
		t.Fatal("Unable to delete certificate from depot")
	}
}

func readCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()

	certPEM, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal("Unable to read certificate")
	}
	pemBlock, _ := pem.Decode(certPEM)
	if pemBlock == nil {
		t.Fatal("Cannot find the next PEM formatted block")
	}
	if pemBlock.Type != "CERTIFICATE" || len(pemBlock.Headers) != 0 {
		t.Fatal("Unmatched type of headers")
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatal("Unable to parse certificate")
	}
	return cert
}

func makeDn(t *testing.T, cert *x509.Certificate) string {
	var dn bytes.Buffer

	if len(cert.Subject.Country) > 0 && len(cert.Subject.Country[0]) > 0 {
		dn.WriteString("/C=" + cert.Subject.Country[0])
	}
	if len(cert.Subject.Province) > 0 && len(cert.Subject.Province[0]) > 0 {
		dn.WriteString("/ST=" + cert.Subject.Province[0])
	}
	if len(cert.Subject.Locality) > 0 && len(cert.Subject.Locality[0]) > 0 {
		dn.WriteString("/L=" + cert.Subject.Locality[0])
	}
	if len(cert.Subject.Organization) > 0 && len(cert.Subject.Organization[0]) > 0 {
		dn.WriteString("/O=" + cert.Subject.Organization[0])
	}
	if len(cert.Subject.OrganizationalUnit) > 0 && len(cert.Subject.OrganizationalUnit[0]) > 0 {
		dn.WriteString("/OU=" + cert.Subject.OrganizationalUnit[0])
	}
	if len(cert.Subject.CommonName) > 0 {
		dn.WriteString("/CN=" + cert.Subject.CommonName)
	}
	if len(cert.EmailAddresses) > 0 {
		dn.WriteString("/emailAddress=" + cert.EmailAddresses[0])
	}
	return dn.String()
}

func envString(key, def string) string {
	if env := os.Getenv(key); env != "" {
		return env
	}
	return def
}
