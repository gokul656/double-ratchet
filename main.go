package main

import "fmt"

type DHKeyPair struct {
	pkey   any
	pubkey any
}

type DoubleRatchet interface {
	GenerateDH() DHKeyPair
	DH(a, b struct{}) any
	KDFRK(rk, DHOut struct{}) (rootKey, chainKey interface{})
	KDFCK(ck struct{}) (chainKey, msgKey interface{})
	Encrypt(mk struct{}, plaintext, optionalData string) []byte
	Decrypt(mk struct{}, ciphertext, optionalData string) []byte
}

func main() {
	bob := NewParticipant()
	alice := NewParticipant()

	fmt.Printf("Alice : %v\n", bob.X3DH(alice))
	fmt.Printf("Bob   : %v\n", alice.X3DH(bob))
}
