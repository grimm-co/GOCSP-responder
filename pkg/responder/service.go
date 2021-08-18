package responder

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github.com/lamassuiot/GOCSP-responder/pkg/crypto/ocsp"
	secrets "github.com/lamassuiot/GOCSP-responder/pkg/secrets/ca"
	"github.com/lamassuiot/GOCSP-responder/pkg/secrets/responder"
)

type Service interface {
	Health(ctx context.Context) bool
	Verify(ctx context.Context, msg []byte) ([]byte, error)
}

type OCSPResponder struct {
	secrets     secrets.Secrets
	respSecrets responder.Secrets
	respCert    *x509.Certificate
	nonceList   [][]byte
}

// takes a list of extensions and returns the nonce extension if it is present
func checkForNonceExtension(exts []pkix.Extension) *pkix.Extension {
	nonce_oid := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
	for _, ext := range exts {
		if ext.Id.Equal(nonce_oid) {
			return &ext
		}
	}
	return nil
}

func (o *OCSPResponder) verifyIssuer(req *ocsp.Request, cas []secrets.Cert) (secrets.Cert, error) {
	for _, ca := range cas {
		h := req.HashAlgorithm.New()
		h.Write(ca.CRT.RawSubject)
		if bytes.Compare(h.Sum(nil), req.IssuerNameHash) != 0 {
			//return errors.New("Issuer name does not match")
			continue
		}
		h.Reset()
		var publicKeyInfo struct {
			Algorithm pkix.AlgorithmIdentifier
			PublicKey asn1.BitString
		}
		if _, err := asn1.Unmarshal(ca.CRT.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
			//return err
			continue
		}
		h.Write(publicKeyInfo.PublicKey.RightAlign())
		if bytes.Compare(h.Sum(nil), req.IssuerKeyHash) != 0 {
			//return errors.New("Issuer key hash does not match")
			continue
		}
		return ca, nil
	}
	return secrets.Cert{}, errors.New("Could no verify the cert's Issuer. No matching issuer found")
}

func (o *OCSPResponder) Health(ctx context.Context) bool {
	return true
}

func (o *OCSPResponder) Verify(ctx context.Context, msg []byte) ([]byte, error) {
	var status int
	var revokedAt time.Time

	// parse the request
	req, exts, err := ocsp.ParseRequest(msg)
	if err != nil {
		return nil, err
	}

	cas, err := o.secrets.GetCAs()
	if err != nil {
		return nil, errors.New("Could not get CAs")
	}
	//make sure the request is valid
	issuerCA, err := o.verifyIssuer(req, cas)
	if err != nil {
		return nil, err
	}

	if issuerCA.Status != secrets.StatusValid {
		fmt.Println("Issuing CA is not valid")
	}

	cert, err := o.secrets.GetCertBigInt(issuerCA.CaName, req.SerialNumber)
	if err != nil {
		return nil, errors.New("Could not get certificate")
	}

	if err != nil {
		status = ocsp.Unknown
	} else {
		if cert.Status == secrets.StatusRevoked || cert.Status == secrets.StatusExpired {
			status = ocsp.Revoked
			tm := time.Unix(cert.RevocationTime, 0)
			revokedAt = tm
		} else if cert.Status == secrets.StatusValid {
			status = ocsp.Good
		}
	}

	// parse key file
	// perhaps I should zero this out after use
	keyi, err := o.respSecrets.GetResponderKey()
	if err != nil {
		return nil, err
	}
	key, ok := keyi.(crypto.Signer)
	if !ok {
		return nil, errors.New("Could not make key a signer")
	}

	// check for nonce extension
	var responseExtensions []pkix.Extension
	nonce := checkForNonceExtension(exts)

	// check if the nonce has been used before
	if o.nonceList == nil {
		o.nonceList = make([][]byte, 10)
	}

	if nonce != nil {
		for _, n := range o.nonceList {
			if bytes.Compare(n, nonce.Value) == 0 {
				return nil, errors.New("This nonce has already been used")
			}
		}

		o.nonceList = append(o.nonceList, nonce.Value)
		responseExtensions = append(responseExtensions, *nonce)
	}

	// construct response template
	rtemplate := ocsp.Response{
		Status:           status,
		SerialNumber:     req.SerialNumber,
		Certificate:      o.respCert,
		RevocationReason: ocsp.Unspecified,
		IssuerHash:       req.HashAlgorithm,
		RevokedAt:        revokedAt,
		ThisUpdate:       time.Now().AddDate(0, 0, -1).UTC(),
		//adding 1 day after the current date. This ocsp library sets the default date to epoch which makes ocsp clients freak out.
		NextUpdate: time.Now().AddDate(0, 0, 1).UTC(),
		Extensions: exts,
	}

	// make a response to return
	resp, err := ocsp.CreateResponse(&issuerCA.CRT, o.respCert, rtemplate, key)
	if err != nil {
		return nil, err
	}
	return resp, nil

}

func NewService(respSecrets responder.Secrets, secrets secrets.Secrets) (Service, error) {
	//the certs should not change, so lets keep them in memory

	respcert, err := respSecrets.GetResponderCert()
	if err != nil {
		return nil, err
	}
	responder := &OCSPResponder{
		secrets:     secrets,
		respSecrets: respSecrets,
		respCert:    respcert,
	}

	return responder, nil
}
