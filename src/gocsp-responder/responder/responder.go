package responder

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type OCSPResponder struct {
	IndexFile    string
	RespKeyFile  string
	RespCertFile string
	CaCertFile   string
	LogFile      string
	LogToStdout  bool
	Strict       bool
	Port         int
	Address      string
	Ssl          bool
	IndexEntries []IndexEntry
	IndexModTime time.Time
	CaCert       *x509.Certificate
	RespCert     *x509.Certificate
}

func Responder() *OCSPResponder {
	return &OCSPResponder{
		IndexFile:    "index.txt",
		RespKeyFile:  "responder.key",
		RespCertFile: "responder.crt",
		CaCertFile:   "ca.crt",
		LogFile:      "/var/log/gocsp-responder.log",
		LogToStdout:  false,
		Strict:       false,
		Port:         8888,
		Address:      "",
		Ssl:          false,
		IndexEntries: nil,
		IndexModTime: time.Time{},
		CaCert:       nil,
		RespCert:     nil,
	}
}

func (self *OCSPResponder) makeHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Print(fmt.Sprintf("Got %s request from %s", r.Method, r.RemoteAddr))
		if self.Strict && r.Header.Get("Content-Type") != "application/ocsp-request" {
			log.Println("Strict mode requires correct Content-Type header")
			return
		}

		b := new(bytes.Buffer)
		switch r.Method {
		case "POST":
			b.ReadFrom(r.Body)
		case "GET":
			gd, _ := base64.StdEncoding.DecodeString(r.URL.Path[1:])
			b.Read(gd)
		default:
			log.Println("Unsupported request method")
			return
		}

		w.Header().Set("Content-Type", "application/ocsp-response")
		resp, err := self.verify(b.Bytes())
		if err != nil {
			log.Print(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		log.Print("Writing response")
		w.Write(resp)
	}
}

//I only know of two types, but more can be added later
const (
	StatusValid   = 'V'
	StatusRevoked = 'R'
	StatusExpired = 'E'
)

type IndexEntry struct {
	Status            byte
	Serial            uint64 //this probably should be a big.Int but I don't see how it would get bigger than a 64 byte int
	IssueTime         time.Time
	RevocationTime    time.Time
	DistinguishedName string
}

//function to parse the index file
func (self *OCSPResponder) parseIndex() error {
	var t string = "060102150405Z"
	finfo, err := os.Stat(self.IndexFile)
	if err == nil {
		if finfo.ModTime().After(self.IndexModTime) {
			log.Print("Index has changed. Updating")
			self.IndexModTime = finfo.ModTime()
			//clear index entries
			self.IndexEntries = self.IndexEntries[:0]
		} else {
			return nil
		}
	} else {
		return err
	}
	if file, err := os.Open(self.IndexFile); err == nil {
		defer file.Close()
		//if we can open it we should be able to stat it
		s := bufio.NewScanner(file)
		for s.Scan() {
			var ie IndexEntry
			ln := strings.Fields(s.Text())
			//probably check for error
			ie.Status = []byte(ln[0])[0]
			ie.IssueTime, _ = time.Parse(t, ln[1])
			//handle strconv errors later
			if ie.Status == StatusValid {
				ie.Serial, _ = strconv.ParseUint(ln[2], 16, 64)
				ie.DistinguishedName = ln[4]
				ie.RevocationTime = time.Time{} //doesn't matter
			} else if ie.Status == StatusRevoked {
				ie.Serial, _ = strconv.ParseUint(ln[3], 16, 64)
				ie.DistinguishedName = ln[5]
				ie.RevocationTime, _ = time.Parse(t, ln[2])
			} else {
				//invalid status or bad line. just carry on
				continue
			}
			self.IndexEntries = append(self.IndexEntries, ie)
		}
	} else {
		return err
	}
	return nil
}

func (self *OCSPResponder) getIndexEntry(s uint64) (*IndexEntry, error) {

	if err := self.parseIndex(); err != nil {
		return nil, err
	}
	for _, ent := range self.IndexEntries {
		if ent.Serial == s {
			return &ent, nil
		}
	}
	return nil, errors.New(fmt.Sprintf("Serial 0x%x not found", s))
}

//function to get and hash the CA cert public key
func parseCertFile(filename string) (*x509.Certificate, error) {
	ct, err := ioutil.ReadFile(filename)
	if err != nil {
		//print out error message here
		return nil, err
	}
	block, _ := pem.Decode(ct)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func parseKeyFile(filename string) (interface{}, error) {
	kt, err := ioutil.ReadFile(filename)
	if err != nil {
		//print out error message here
		return nil, err
	}
	block, _ := pem.Decode(kt)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

//takes the der encoded ocsp request and verifies it
func (self *OCSPResponder) verify(rawreq []byte) ([]byte, error) {
	var status int
	var revokedAt time.Time
	req, err := ocsp.ParseRequest(rawreq)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	ent, err := self.getIndexEntry(req.SerialNumber.Uint64())
	if err != nil {
		log.Println(err)
		status = ocsp.Unknown
	} else {
		log.Print(fmt.Sprintf("Found entry %+v", ent))
		if ent.Status == StatusRevoked {
			log.Print("This certificate is revoked")
			status = ocsp.Revoked
			revokedAt = ent.RevocationTime
		} else if ent.Status == StatusValid {
			log.Print("This certificate is valid")
			status = ocsp.Good
		}
	}

	//perhaps I should zero this out after use
	keyi, err := parseKeyFile(self.RespKeyFile)
	if err != nil {
		return nil, err
	}

	key, ok := keyi.(crypto.Signer)
	if !ok {
		return nil, errors.New("Could not make key a signer")
	}

	rtemplate := ocsp.Response{
		Status:           status,
		SerialNumber:     req.SerialNumber,
		Certificate:      self.RespCert,
		RevocationReason: ocsp.Unspecified,
		RevokedAt:        revokedAt,
		ThisUpdate:       self.IndexModTime,
		NextUpdate:       time.Now().AddDate(0, 0, 30), //adding 30 days to the current date. This ocsp library sets the default date to epoch which makes ocsp clients freak out.
		ExtraExtensions:  nil,
	}

	resp, err := ocsp.CreateResponse(self.CaCert, self.RespCert, rtemplate, key)
	if err != nil {
		return nil, err
	}

	return resp, err
}

func (self *OCSPResponder) Serve() error {
	if !self.LogToStdout {
		lf, err := os.OpenFile(self.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatal("Could not open log file " + self.LogFile)
		}
		defer lf.Close()
		log.SetOutput(lf)
	}

	//the certs should not change, so lets keep them in memory
	cacert, err := parseCertFile(self.CaCertFile)
	if err != nil {
		log.Fatal(err)
		return err
	}
	respcert, err := parseCertFile(self.RespCertFile)
	if err != nil {
		log.Fatal(err)
		return err
	}

	self.CaCert = cacert
	self.RespCert = respcert

	handler := self.makeHandler()
	http.HandleFunc("/", handler)
	log.Println(fmt.Sprintf("GOCSP-Responder starting on %s:%d", self.Address, self.Port))
	http.ListenAndServe(fmt.Sprintf("%s:%d", self.Address, self.Port), nil)
	return nil
}
