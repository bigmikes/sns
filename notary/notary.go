package notary

import (
	"crypto/sha512"
	"time"
)

type SignedPayload struct {
	Ts        string
	Payload   []byte
	Signature []byte
}

type Notary struct {
}

func NewNotary() *Notary {
	return &Notary{}
}

func (n *Notary) SignPayload(p []byte) SignedPayload {
	t := time.Now().Format(time.RFC3339Nano)
	toSign := []byte(t)
	toSign = append(toSign, p...)
	sha := sha512.Sum512(toSign)

	return SignedPayload{
		Ts:        t,
		Payload:   p,
		Signature: sha[:],
	}
}
