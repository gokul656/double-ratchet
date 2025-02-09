package main

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
	proof()
}
