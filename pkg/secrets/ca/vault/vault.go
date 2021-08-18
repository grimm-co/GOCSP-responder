package vault

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	secrets "github.com/lamassuiot/GOCSP-responder/pkg/secrets/ca"

	"github.com/hashicorp/vault/api"
)

type vaultSecrets struct {
	logger   log.Logger
	client   *api.Client
	roleID   string
	secretID string
	CA       string
}

func NewVaultSecrets(address string, roleID string, secretID string, CA string, logger log.Logger) (*vaultSecrets, error) {
	conf := api.DefaultConfig()
	conf.Address = strings.ReplaceAll(conf.Address, "https://127.0.0.1:8200", address)
	tlsConf := &api.TLSConfig{CACert: CA}
	conf.ConfigureTLS(tlsConf)
	client, err := api.NewClient(conf)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not create Vault API client")
		return nil, err
	}

	err = login(client, roleID, secretID)
	if err != nil {
		level.Error(logger).Log("err", err, "msg", "Could not login into Vault")
		return nil, err
	}
	return &vaultSecrets{client: client, roleID: roleID, secretID: secretID, logger: logger}, nil
}

func login(client *api.Client, roleID string, secretID string) error {
	loginPath := "auth/approle/login"
	options := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}
	resp, err := client.Logical().Write(loginPath, options)
	if err != nil {
		return err
	}
	client.SetToken(resp.Auth.ClientToken)
	return nil
}

func (vs *vaultSecrets) GetCAs() ([]secrets.Cert, error) {
	resp, err := vs.client.Sys().ListMounts()
	if err != nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not obtain list of Vault mounts")
		return []secrets.Cert{}, err
	}
	var CAs []secrets.Cert

	for mount, mountOutput := range resp {
		if mountOutput.Type == "pki" {
			caName := strings.TrimSuffix(mount, "/")
			cert, err := vs.GetCACert(caName)
			if err != nil {
				level.Error(vs.logger).Log("err", err, "msg", "Could not get CA cert for "+caName)
				continue
			}

			CAs = append(CAs, cert)
		}
	}
	level.Info(vs.logger).Log("msg", strconv.Itoa(len(CAs))+" obtained from Vault mounts")
	return CAs, nil
}

func (vs *vaultSecrets) GetCACert(caName string) (secrets.Cert, error) {
	resp, err := vs.client.Logical().Read(caName + "/cert/ca")
	if err != nil {
		level.Warn(vs.logger).Log("err", err, "msg", "Could not read "+caName+" certificate from Vault")
		return secrets.Cert{}, err
	}
	if resp == nil {
		level.Warn(vs.logger).Log("Mount path for PKI " + caName + " does not have a root CA")
		return secrets.Cert{}, err
	}
	cert, err := decodeCert(caName, []byte(resp.Data["certificate"].(string)))
	if err != nil {
		err = errors.New("Cannot decode cert. Perhaps it is malphormed")
		level.Warn(vs.logger).Log("err", err)
		return secrets.Cert{}, err
	}

	hasExpired := cert.NotAfter.Before(time.Now())
	status := secrets.StatusValid
	if hasExpired {
		status = secrets.StatusExpired
	}

	if !vs.hasEnrollerRole(caName) {
		status = secrets.StatusRevoked
	}

	return secrets.Cert{
		SerialNumber: insertNth(toHexInt(cert.SerialNumber), 2),
		Status:       status,
		CaName:       caName,
		CN:           cert.Subject.CommonName,
		CRT:          cert,
		ValidFrom:    cert.NotBefore.String(),
		ValidTo:      cert.NotAfter.String(),
	}, nil
}

func (vs *vaultSecrets) GetCertBigInt(caName string, serialNumber *big.Int) (secrets.Cert, error) {
	return vs.GetCert(caName, insertNth(toHexInt(serialNumber), 2))
}

func (vs *vaultSecrets) GetCert(caName string, serialNumber string) (secrets.Cert, error) {
	certResponse, err := vs.client.Logical().Read(caName + "/cert/" + serialNumber)
	if err != nil || certResponse == nil {
		level.Error(vs.logger).Log("err", err, "msg", "Could not read cert with serial number "+serialNumber+" from CA "+caName)
		return secrets.Cert{}, errors.New("Could not read cert with serial number " + serialNumber + " from CA " + caName)
	}
	cert, err := decodeCert(caName, []byte(certResponse.Data["certificate"].(string)))
	hasExpired := cert.NotAfter.Before(time.Now())
	status := secrets.StatusValid
	if hasExpired {
		status = secrets.StatusExpired
	}
	revocation_time, err := certResponse.Data["revocation_time"].(json.Number).Int64()
	if err != nil {
		err = errors.New("revocation_time not an INT for cert " + serialNumber)
		level.Warn(vs.logger).Log("err", err)
	}
	if revocation_time != 0 {
		status = secrets.StatusRevoked
	}
	return secrets.Cert{
		SerialNumber:   insertNth(toHexInt(cert.SerialNumber), 2),
		Status:         status,
		CaName:         caName,
		RevocationTime: revocation_time,
		ValidFrom:      cert.NotBefore.String(),
		ValidTo:        cert.NotAfter.String(),
		CN:             cert.Subject.CommonName,
	}, nil
}

func decodeCert(caName string, cert []byte) (x509.Certificate, error) {
	pemBlock, _ := pem.Decode(cert)
	if pemBlock == nil {
		err := errors.New("Cannot find the next formatted block")
		// level.Error(vs.logger).Log("err", err)
		return x509.Certificate{}, err
	}
	if pemBlock.Type != "CERTIFICATE" || len(pemBlock.Headers) != 0 {
		err := errors.New("Unmatched type of headers")
		// level.Error(vs.logger).Log("err", err)
		return x509.Certificate{}, err
	}
	caCert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		// level.Error(vs.logger).Log("err", err, "msg", "Could not parse "+caName+" CA certificate")
		return x509.Certificate{}, err
	}
	return *caCert, nil
}

func (vs *vaultSecrets) hasEnrollerRole(caName string) bool {
	data, _ := vs.client.Logical().Read(caName + "/roles/enroller")
	if data == nil {
		return false
	} else {
		return true
	}
}

func getPublicKeyInfo(cert x509.Certificate) string {
	publicKeyDer, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	publicKeyBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDer,
	}
	publicKeyPem := string(pem.EncodeToMemory(&publicKeyBlock))
	return publicKeyPem
}

func insertNth(s string, n int) string {
	if len(s)%2 != 0 {
		s = "0" + s
	}
	var buffer bytes.Buffer
	var n_1 = n - 1
	var l_1 = len(s) - 1
	for i, rune := range s {
		buffer.WriteRune(rune)
		if i%n == n_1 && i != l_1 {
			buffer.WriteRune('-')
		}
	}
	return buffer.String()
}

func toHexInt(n *big.Int) string {
	return fmt.Sprintf("%x", n) // or %X or upper case
}
