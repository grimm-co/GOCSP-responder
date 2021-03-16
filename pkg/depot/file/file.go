package file

import (
	"bufio"
	"bytes"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/lamassuiot/GOCSP-responder/pkg/depot"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

type file struct {
	indexFile    string
	indexEntries []depot.IndexEntry
	indexModTime time.Time
	logger       log.Logger
}

func NewFile(indexFile string, logger log.Logger) depot.Depot {
	return &file{indexFile: indexFile, logger: logger}
}

func (f *file) GetIndexEntry(serial *big.Int) (*depot.IndexEntry, error) {
	serialHex := fmt.Sprintf("0x%x", serial)
	level.Info(f.logger).Log("msg", "Looking for serial "+serialHex)
	if err := f.parseIndex(); err != nil {
		level.Error(f.logger).Log("err", err, "msg", "Could not parse Index File")
		return nil, err
	}
	for _, ent := range f.indexEntries {
		if ent.Serial.Cmp(serial) == 0 {
			level.Info(f.logger).Log("msg", "Serial "+serialHex+" found in Index File")
			return &ent, nil
		}
	}
	err := fmt.Errorf("Serial 0x%x not found", serial)
	level.Error(f.logger).Log("err", err, "msg", "Could not find serial "+serialHex+" in Index File")
	return nil, err
}

func (f *file) RevokeCertificate(ie *depot.IndexEntry) error {
	if err := f.parseIndex(); err != nil {
		level.Error(f.logger).Log("err", err, "msg", "Could not parse Index File")
		return err
	}
	for i, ent := range f.indexEntries {
		if ent.Serial.Cmp(ie.Serial) == 0 {
			level.Info(f.logger).Log("msg", "Revoking Index Entry with serial "+fmt.Sprintf("0x%x", ie.Serial))
			f.indexEntries[i].Status = []byte("R")[0]
		}
	}
	return f.overwriteIndex()
}

func (f *file) InsertCertificate(ie *depot.IndexEntry) error {
	file, err := os.OpenFile(f.indexFile, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		level.Error(f.logger).Log("err", err, "msg", "Could not open Index File to append a new entry")
		return err
	}
	defer file.Close()
	level.Info(f.logger).Log("msg", "Index File oppened to insert new Index Entry with serial "+fmt.Sprintf("0x%x", ie.Serial))

	var fileEntry bytes.Buffer
	status := string(ie.Status)
	serialHex := fmt.Sprintf("%X", ie.Serial)
	if len(serialHex)%2 == 1 {
		serialHex = fmt.Sprintf("0%s", ie.Serial)
	}
	issueTime := makeOpenSSLTime(ie.IssueTime)
	revocationTime := makeOpenSSLTime(ie.RevocationTime)
	dn := ie.DistinguishedName
	fileEntry.WriteString(status + "\t")
	fileEntry.WriteString(issueTime + "\t")
	fileEntry.WriteString(revocationTime + "\t")
	fileEntry.WriteString(serialHex + "\t")
	fileEntry.WriteString(ie.CertPath + "\t")
	fileEntry.WriteString(dn)
	fileEntry.WriteString("\n")

	if _, err := file.Write(fileEntry.Bytes()); err != nil {
		level.Error(f.logger).Log("err", err, "msg", "Could not insert Index Entry with serial "+fmt.Sprintf("0x%x", ie.Serial)+" in Index File")
		return err
	}
	level.Info(f.logger).Log("msg", "Index Entry with serial "+fmt.Sprintf("0x%x", ie.Serial)+" inserted in Index File")
	return nil
}

func (f *file) DeleteCertificate(ie *depot.IndexEntry) error {
	if err := f.parseIndex(); err != nil {
		level.Error(f.logger).Log("err", err, "msg", "Could not parse Index File")
		return err
	}
	for i, ent := range f.indexEntries {
		if ent.Serial.Cmp(ie.Serial) == 0 {
			level.Info(f.logger).Log("msg", "Deleting Index Entry with serial "+fmt.Sprintf("0x%x", ie.Serial))
			f.indexEntries = f.removeIndexEntry(f.indexEntries, i)
		}
	}
	return f.overwriteIndex()
}

func (f *file) removeIndexEntry(indexEntries []depot.IndexEntry, position int) []depot.IndexEntry {
	return append(indexEntries[:position], indexEntries[position+1:]...)
}

func (f *file) overwriteIndex() error {
	file, err := os.OpenFile(f.indexFile, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		level.Error(f.logger).Log("err", err, "msg", "Could not open Index File to overwrite the content")
		return err
	}
	defer file.Close()
	level.Info(f.logger).Log("msg", "Index File oppened to overwrite the content")

	err = file.Truncate(0)
	for _, ent := range f.indexEntries {
		var fileEntry bytes.Buffer
		status := string(ent.Status)
		serialHex := fmt.Sprintf("%X", ent.Serial)
		if len(serialHex)%2 == 1 {
			serialHex = fmt.Sprintf("0%s", ent.Serial)
		}
		issueTime := makeOpenSSLTime(ent.IssueTime)
		revocationTime := makeOpenSSLTime(ent.RevocationTime)
		dn := ent.DistinguishedName
		fileEntry.WriteString(status + "\t")
		fileEntry.WriteString(issueTime + "\t")
		fileEntry.WriteString(revocationTime + "\t")
		fileEntry.WriteString(serialHex + "\t")
		fileEntry.WriteString(ent.CertPath + "\t")
		fileEntry.WriteString(dn)
		fileEntry.WriteString("\n")
		if _, err := file.Write(fileEntry.Bytes()); err != nil {
			level.Error(f.logger).Log("err", err, "msg", "Could not insert Index Entry with serial "+serialHex+" in Index File")
			return err
		}
	}
	level.Info(f.logger).Log("msg", "Index File overwritted")
	return nil

}

// function to parse the index file
func (f *file) parseIndex() error {
	var t string = "060102150405Z"
	finfo, err := os.Stat(f.indexFile)
	if err == nil {
		// if the file modtime has changed, then reload the index file
		if finfo.ModTime().After(f.indexModTime) {
			level.Info(f.logger).Log("msg", "Index has changed. Updating")
			f.indexModTime = finfo.ModTime()
			// clear index entries
			f.indexEntries = f.indexEntries[:0]
		} else {
			level.Info(f.logger).Log("msg", "Index has not changed")
			// the index has not changed. just return
			return nil
		}
	} else {
		return err
	}

	// open and parse the index file
	if file, err := os.Open(f.indexFile); err == nil {
		defer file.Close()
		s := bufio.NewScanner(file)
		for s.Scan() {
			var ie depot.IndexEntry
			ln := strings.Fields(s.Text())
			ie.Status = []byte(ln[0])[0]
			ie.IssueTime, _ = time.Parse(t, ln[1])
			if ie.Status == depot.StatusValid {
				ie.Serial, _ = new(big.Int).SetString(ln[2], 16)
				ie.DistinguishedName = ln[4]
				ie.RevocationTime = time.Time{} //doesn't matter
			} else if ie.Status == depot.StatusRevoked {
				ie.Serial, _ = new(big.Int).SetString(ln[3], 16)
				ie.DistinguishedName = ln[5]
				ie.RevocationTime, _ = time.Parse(t, ln[2])
			} else {
				// invalid status or bad line. just carry on
				continue
			}
			f.indexEntries = append(f.indexEntries, ie)
		}
	} else {
		return err
	}
	return nil
}

func makeOpenSSLTime(t time.Time) string {
	y := (int(t.Year()) % 100)
	validDate := fmt.Sprintf("%02d%02d%02d%02d%02d%02dZ", y, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
	return validDate
}
