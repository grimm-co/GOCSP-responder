package file

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"github.com/lamassuiot/GOCSP-responder/pkg/secrets/ca"
	"github.com/lamassuiot/GOCSP-responder/pkg/utils"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

type file struct {
	cert   string
	logger log.Logger
}

func NewFile(cert string, logger log.Logger) ca.Secrets {
	return &file{cert, logger}
}

func (f *file) GetCACert() (*x509.Certificate, error) {
	certPEM, err := ioutil.ReadFile(f.cert)
	if err != nil {
		level.Error(f.logger).Log("err", err, "msg", "Could not load CA certificate")
		return nil, err
	}
	pemBlock, _ := pem.Decode(certPEM)
	err = utils.CheckPEMBlock(pemBlock, utils.CertPEMBlockType)
	if err != nil {
		level.Error(f.logger).Log("err", err, "msg", "Could not check PEM block of CA certificate")
		return nil, err
	}
	level.Info(f.logger).Log("msg", "CA certificate loaded")
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		level.Error(f.logger).Log("err", err, "msg", "Could not parse CA certificate")
		return nil, err
	}
	level.Info(f.logger).Log("msg", "CA certificate parsed")
	return cert, nil
}
