package vault

import (
	"crypto/x509"
	"encoding/pem"
	"strings"

	"github.com/lamassuiot/GOCSP-responder/pkg/secrets/ca"
	"github.com/lamassuiot/GOCSP-responder/pkg/utils"

	"github.com/hashicorp/vault/api"
)

type vaultSecrets struct {
	client   *api.Client
	roleID   string
	secretID string
	CA       string
}

func NewVaultSecrets(address string, roleID string, secretID string, CA string) (ca.Secrets, error) {
	conf := api.DefaultConfig()
	conf.Address = strings.ReplaceAll(conf.Address, "https://127.0.0.1:8200", address)
	tlsConf := &api.TLSConfig{Insecure: true}
	conf.ConfigureTLS(tlsConf)
	client, err := api.NewClient(conf)
	if err != nil {
		return nil, err
	}

	err = login(client, roleID, secretID)
	if err != nil {
		return nil, err
	}
	return &vaultSecrets{client: client, roleID: roleID, secretID: secretID, CA: CA}, nil
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

func (vs *vaultSecrets) GetCACert() (*x509.Certificate, error) {
	caPath := vs.CA + "/cert/ca"
	resp, err := vs.client.Logical().Read(caPath)
	if err != nil {
		return nil, err
	}
	pemBlock, _ := pem.Decode([]byte(resp.Data["certificate"].(string)))
	err = utils.CheckPEMBlock(pemBlock, utils.CertPEMBlockType)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return caCert, nil
}
