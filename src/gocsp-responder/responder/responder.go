package responder

import (
	"bufio"
	"encoding/base64"
	_ "encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/ocsp"
	_ "io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type OCSPResponder struct {
	IndexFile string
	CaKey     string
	CaCert    string
	Strict    bool
	Port      int
	Address   string
	Ssl       bool
}

func Responder() *OCSPResponder {
	return &OCSPResponder{
		IndexFile: "index.txt",
		CaKey:     "ca.key",
		CaCert:    "ca.crt",
		Strict:    false,
		Port:      8888,
		Address:   "",
		Ssl:       false,
	}
}

func (self *OCSPResponder) makeHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if self.Strict && r.Header.Get("Content-Type") != "application/ocsp-request" {
			fmt.Println("Strict mode requires correct Content-Type header")
			return
		}
		var b []byte
		switch r.Method {
		case "POST":
			r.Body.Read(b)
		case "GET":
			b, _ = base64.StdEncoding.DecodeString(r.URL.Path[1:])
		default:
			fmt.Println("Unsupported request method")
			return
		}
		status, err := self.verify(b)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(status)
	}
}

//I only know of two types, but more can be added later
const (
	StatusValid   = 'V'
	StatusRevoked = 'R'
)

type IndexEntry struct {
	Status byte
	Serial uint64 //this probably should be a big.Int but I don't see how it would get bigger than a 64 byte int
	//todo add revoke time and maybe reason
	DistinguishedName string
}

//function to parse the index file, return as a list of IndexEntries
func (self *OCSPResponder) parseIndex() ([]IndexEntry, error) {
	var ret []IndexEntry
	if file, err := os.Open(self.IndexFile); err == nil {
		defer file.Close()
		s := bufio.NewScanner(file)
		for s.Scan() {
			var ie IndexEntry
			ln := strings.Fields(s.Text())
			fmt.Println(ln)
			//probably check for error
			ie.Status = []byte(ln[0])[0]
			//handle strconv errors later
			if ie.Status == StatusValid {
				ie.Serial, _ = strconv.ParseUint(ln[2], 16, 64)
				ie.DistinguishedName = ln[4]
			} else if ie.Status == StatusRevoked {
				ie.Serial, _ = strconv.ParseUint(ln[3], 16, 64)
				ie.DistinguishedName = ln[5]
			} else {
				//invalid status or bad line. just carry on
				continue
			}
			ret = append(ret, ie)
		}
	} else {
		return nil, errors.New("Could not open index file")
	}
	return ret, nil
}

func (self *OCSPResponder) getIndexEntry(s uint64) (*IndexEntry, error) {
	ents, err := self.parseIndex()
	if err != nil {
		return nil, err
	}
	for _, ent := range ents {
		if ent.Serial == s {
			return &ent, nil
		}
	}
	return nil, errors.New("Serial not found")
}

//function to get and hash CA key DN

//function to get and hash the CA cert public key

//takes the der encoded ocsp request and verifies it
func (self *OCSPResponder) verify(rawreq []byte) (bool, error) {
	req, err := ocsp.ParseRequest(rawreq)
	ent, err := self.getIndexEntry(req.SerialNumber.Uint64())
	fmt.Println(ent.DistinguishedName)
	return true, err
}

func (self *OCSPResponder) Serve() {
	handler := self.makeHandler()
	http.HandleFunc("/", handler)
	http.ListenAndServe(fmt.Sprintf("%s:%d", self.Address, self.Port), nil)
}
