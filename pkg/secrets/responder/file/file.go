package file

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"github.com/lamassuiot/GOCSP-responder/pkg/secrets/responder"
	"github.com/lamassuiot/GOCSP-responder/pkg/utils"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

type file struct {
	key    string
	cert   string
	logger log.Logger
}

func NewFile(key string, cert string, logger log.Logger) responder.Secrets {
	return &file{key: key, cert: cert, logger: logger}
}

func (f *file) GetResponderCert() (*x509.Certificate, error) {
	certPEM, err := ioutil.ReadFile(f.cert)
	if err != nil {
		level.Error(f.logger).Log("err", err, "msg", "Could not load Responder certificate")
		return nil, err
	}
	pemBlock, _ := pem.Decode(certPEM)
	err = utils.CheckPEMBlock(pemBlock, utils.CertPEMBlockType)
	if err != nil {
		level.Error(f.logger).Log("err", err, "msg", "Could not check PEM block of Responder certificate")
		return nil, err
	}
	level.Info(f.logger).Log("msg", "Responder certificate loaded")
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		level.Error(f.logger).Log("err", err, "msg", "Could not parse Responder certificate")
		return nil, err
	}
	level.Info(f.logger).Log("msg", "Responder certificate parsed")
	return cert, nil

}

func (f *file) GetResponderKey() (crypto.PrivateKey, error) {
	keyPEM, err := ioutil.ReadFile(f.key)
	if err != nil {
		level.Error(f.logger).Log("err", err, "msg", "Could not load Responder key")
		return nil, err
	}
	pemBlock, _ := pem.Decode(keyPEM)
	err = utils.CheckPEMBlock(pemBlock, utils.KeyPEMBlockType)
	if err != nil {
		level.Error(f.logger).Log("err", err, "msg", "Could not check PEM block of Responder key")
		return nil, err
	}
	level.Info(f.logger).Log("msg", "Responder key loaded")
	key, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		level.Error(f.logger).Log("err", err, "msg", "Could not parse Responder key")
		return nil, err
	}
	level.Info(f.logger).Log("msg", "Responder key parsed")
	return key, nil
}

func (f *file) GetResponderCertFile() string {
	return f.cert
}

func (f *file) GetResponderKeyFile() string {
	return f.key
}
