package utils

import (
	"encoding/pem"
	"errors"
)

const (
	CertPEMBlockType = "CERTIFICATE"
	KeyPEMBlockType  = "RSA PRIVATE KEY"
)

func CheckPEMBlock(pemBlock *pem.Block, blockType string) error {
	if pemBlock == nil {
		return errors.New("cannot find the next PEM formatted block")
	}
	if pemBlock.Type != blockType || len(pemBlock.Headers) != 0 {
		return errors.New("unmatched type of headers")
	}
	return nil
}
