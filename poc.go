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

type Bob struct {
	IdentityKey ed25519.PrivateKey
	OneTimeKey  ed25519.PrivateKey
	SignedKey   ed25519.PrivateKey
}

func NewBob() *Bob {
	_, ikPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, okPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, sPriv, _ := ed25519.GenerateKey(rand.Reader)

	return &Bob{
		IdentityKey: ikPriv,
		OneTimeKey:  okPriv,
		SignedKey:   sPriv,
	}
}

func (b *Bob) XD3H(a *Alice) string {
	bSignedKeyPub, _ := publicKeyToBytes(b.SignedKey.Public())
	bIdentityKeyPub, _ := publicKeyToBytes(b.IdentityKey.Public())
	bOneTimeKeyPub, _ := publicKeyToBytes(b.OneTimeKey.Public())

	alicebIdentityKeyPub, _ := publicKeyToBytes(a.IdentityKey.Public())
	alicebEphemeralKeyPub, _ := publicKeyToBytes(a.EphemeralKey.Public())

	dh1, _ := computeSharedSecret(bSignedKeyPub, alicebIdentityKeyPub)
	dh2, _ := computeSharedSecret(bIdentityKeyPub, alicebEphemeralKeyPub)
	dh3, _ := computeSharedSecret(bSignedKeyPub, alicebEphemeralKeyPub)
	dh4, _ := computeSharedSecret(bOneTimeKeyPub, alicebEphemeralKeyPub)

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

type Alice struct {
	IdentityKey  ed25519.PrivateKey
	EphemeralKey ed25519.PrivateKey
}

func NewAlice() *Alice {
	_, ikPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, ephPriv, _ := ed25519.GenerateKey(rand.Reader)

	return &Alice{
		IdentityKey:  ikPriv,
		EphemeralKey: ephPriv,
	}
}

func (a *Alice) XD3H(b *Bob) string {
	bSignedKeyPub, _ := publicKeyToBytes(b.SignedKey.Public())
	bIdentityKeyPub, _ := publicKeyToBytes(b.IdentityKey.Public())
	bOneTimeKeyPub, _ := publicKeyToBytes(b.OneTimeKey.Public())

	alicebIdentityKeyPub, _ := publicKeyToBytes(a.IdentityKey.Public())
	alicebEphemeralKeyPub, _ := publicKeyToBytes(a.EphemeralKey.Public())

	dh1, _ := computeSharedSecret(alicebIdentityKeyPub, bSignedKeyPub)
	dh2, _ := computeSharedSecret(alicebEphemeralKeyPub, bIdentityKeyPub)
	dh3, _ := computeSharedSecret(alicebEphemeralKeyPub, bSignedKeyPub)
	dh4, _ := computeSharedSecret(alicebEphemeralKeyPub, bOneTimeKeyPub)

	combinedDH := append(dh1, dh2...)
	combinedDH = append(combinedDH, dh3...)
	combinedDH = append(combinedDH, dh4...)

	return HKDF(combinedDH)
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
