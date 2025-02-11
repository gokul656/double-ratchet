package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type Participant struct {
	IdentityKey  ed25519.PrivateKey
	EphemeralKey ed25519.PrivateKey
	SignedKey    ed25519.PrivateKey
	OneTimeKey   ed25519.PrivateKey
}

func NewParticipant() *Participant {
	_, ikPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, ephPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, sPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, otPriv, _ := ed25519.GenerateKey(rand.Reader)

	return &Participant{
		IdentityKey:  ikPriv,
		EphemeralKey: ephPriv,
		SignedKey:    sPriv,
		OneTimeKey:   otPriv,
	}
}

func (p *Participant) X3DH(other *Participant) string {
	selfSignedKeyPub, _ := publicKeyToBytes(p.SignedKey.Public())
	selfIdentityKeyPub, _ := publicKeyToBytes(p.IdentityKey.Public())
	selfOneTimeKeyPub, _ := publicKeyToBytes(p.OneTimeKey.Public())

	otherIdentityKeyPub, _ := publicKeyToBytes(other.IdentityKey.Public())
	otherEphemeralKeyPub, _ := publicKeyToBytes(other.EphemeralKey.Public())

	dh1, _ := computeSharedSecret(selfSignedKeyPub, otherIdentityKeyPub)
	dh2, _ := computeSharedSecret(selfIdentityKeyPub, otherEphemeralKeyPub)
	dh3, _ := computeSharedSecret(selfSignedKeyPub, otherEphemeralKeyPub)
	dh4, _ := computeSharedSecret(selfOneTimeKeyPub, otherEphemeralKeyPub)

	combinedDH := append(dh1, dh2...)
	combinedDH = append(combinedDH, dh3...)
	combinedDH = append(combinedDH, dh4...)

	return HKDF(combinedDH)
}

func computeSharedSecret(publicKey, privateKey []byte) ([]byte, error) {
	var sharedSecret []byte
	_, err := curve25519.X25519(privateKey, publicKey[:])
	if err != nil {
		return []byte{}, err
	}
	return sharedSecret, nil
}

func publicKeyToBytes(pubKey crypto.PublicKey) ([]byte, error) {
	switch key := pubKey.(type) {
	case []byte:
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pubKey)
	}
}

func HKDF(combinedDH []byte) string {
	hkdf := hkdf.New(sha256.New, combinedDH, nil, nil)

	sharedKey := make([]byte, 32)
	_, err := io.ReadFull(hkdf, sharedKey)
	if err != nil {
		return ""
	}

	return base64.StdEncoding.EncodeToString(sharedKey)
}
