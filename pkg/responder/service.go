package responder

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"time"

	"github.com/lamassuiot/GOCSP-responder/pkg/crypto/ocsp"
	"github.com/lamassuiot/GOCSP-responder/pkg/depot"
	"github.com/lamassuiot/GOCSP-responder/pkg/secrets/ca"
	"github.com/lamassuiot/GOCSP-responder/pkg/secrets/responder"
)

type Service interface {
	Health(ctx context.Context) bool
	Verify(ctx context.Context, msg []byte) ([]byte, error)
}

type OCSPResponder struct {
	caSecrets   ca.Secrets
	respSecrets responder.Secrets
	depot       depot.Depot
	caCert      *x509.Certificate
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

func (o *OCSPResponder) verifyIssuer(req *ocsp.Request) error {
	h := req.HashAlgorithm.New()
	h.Write(o.caCert.RawSubject)
	if bytes.Compare(h.Sum(nil), req.IssuerNameHash) != 0 {
		return errors.New("Issuer name does not match")
	}
	h.Reset()
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(o.caCert.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return err
	}
	h.Write(publicKeyInfo.PublicKey.RightAlign())
	if bytes.Compare(h.Sum(nil), req.IssuerKeyHash) != 0 {
		return errors.New("Issuer key hash does not match")
	}
	return nil
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

	//make sure the request is valid
	if err := o.verifyIssuer(req); err != nil {
		return nil, err
	}

	// get the index entry, if it exists
	ent, err := o.depot.GetIndexEntry(req.SerialNumber)
	if err != nil {
		status = ocsp.Unknown
	} else {
		if ent.Status == depot.StatusRevoked {
			status = ocsp.Revoked
			revokedAt = ent.RevocationTime
		} else if ent.Status == depot.StatusValid {
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
	resp, err := ocsp.CreateResponse(o.caCert, o.respCert, rtemplate, key)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func NewService(caSecrets ca.Secrets, respSecrets responder.Secrets, depot depot.Depot) (Service, error) {
	//the certs should not change, so lets keep them in memory
	cacert, err := caSecrets.GetCACert()
	if err != nil {
		return nil, err
	}
	respcert, err := respSecrets.GetResponderCert()
	if err != nil {
		return nil, err
	}
	responder := &OCSPResponder{
		caSecrets:   caSecrets,
		respSecrets: respSecrets,
		depot:       depot,
		caCert:      cacert,
		respCert:    respcert,
	}

	return responder, nil
}
