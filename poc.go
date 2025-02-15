package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type DoubleRatchet interface {
}

type Participant struct {
	IdentityKey  ed25519.PrivateKey
	EphemeralKey ed25519.PrivateKey
	SignedKey    ed25519.PrivateKey
	OneTimeKey   ed25519.PrivateKey
	RootKey      []byte
	ChainKey     []byte
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
	combinedDH, _ := computeSharedSecret(p.SignedKey.Seed(), other.IdentityKey.Public().(ed25519.PublicKey))

	ratchet, _ := deriveRootAndChainKey(combinedDH)
	p.RootKey = ratchet.RootKey
	p.ChainKey = ratchet.ChainKey

	return HKDF(combinedDH)
}

func deriveRootAndChainKey(secret []byte) (*Participant, error) {
	hkdf := hkdf.New(sha256.New, secret, nil, []byte("Root and Chain Key Derivation"))
	rootKey := make([]byte, 32)
	chainKey := make([]byte, 32)

	io.ReadFull(hkdf, rootKey)
	io.ReadFull(hkdf, chainKey)

	return &Participant{
		RootKey:  rootKey,
		ChainKey: chainKey,
	}, nil
}

func DeriveMessageKey(chainKey []byte) ([]byte, []byte) {
	h := hmac.New(sha256.New, chainKey)
	h.Write([]byte("message key derivation"))
	messageKey := h.Sum(nil)

	h.Reset()
	h.Write([]byte("next chain key derivation"))
	nextChainKey := h.Sum(nil)

	return messageKey, nextChainKey
}

func Encrypt(plaintext string, messageKey []byte) (string, []byte, error) {
	block, err := aes.NewCipher(messageKey)
	if err != nil {
		return "", nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	io.ReadFull(rand.Reader, nonce)

	cipherText := aesGCM.Seal(nil, nonce, []byte(plaintext), nil)
	finalCipher := append(nonce, cipherText...)

	return base64.StdEncoding.EncodeToString(finalCipher), nonce, nil
}

func Decrypt(base64String string, messageKey []byte) (string, error) {
	encrypted, _ := base64.StdEncoding.DecodeString(base64String)

	block, _ := aes.NewCipher(messageKey)
	aesGCM, _ := cipher.NewGCM(block)

	nonceSize := aesGCM.NonceSize()
	if len(encrypted) < nonceSize {
		return "", fmt.Errorf("invalid ciphertext")
	}

	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func computeSharedSecret(publicKey, privateKey []byte) ([]byte, error) {
	var sharedSecret []byte
	_, err := curve25519.X25519(privateKey, publicKey)
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
	io.ReadFull(hkdf, sharedKey)

	return base64.StdEncoding.EncodeToString(sharedKey)
}
