package notary

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"time"
)

type SignedPayload struct {
	Ts        string
	Payload   []byte
	Signature []byte
}

type Notary struct {
	prvKey *rsa.PrivateKey
}

func NewNotary(ecCertFile string) (*Notary, error) {
	f, err := os.Open(ecCertFile)
	if err != nil {
		return nil, err
	}
	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode(buf)
	if p == nil {
		return nil, errors.New("no pem block found")
	}
	key, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		return nil, err
	}
	return &Notary{
		prvKey: key,
	}, nil
}

func (n *Notary) SignPayload(p []byte) (SignedPayload, error) {
	t := time.Now().Format(time.RFC3339Nano)
	toSign := []byte(t)
	toSign = append(toSign, p...)
	hashed := sha256.Sum256(toSign)

	signature, err := rsa.SignPKCS1v15(rand.Reader, n.prvKey, crypto.SHA256, hashed[:])
	if err != nil {
		return SignedPayload{}, err
	}

	return SignedPayload{
		Ts:        t,
		Payload:   p,
		Signature: signature,
	}, nil
}
