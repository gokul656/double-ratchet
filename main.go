package main

import "fmt"

func main() {
	bob := NewParticipant()
	alice := NewParticipant()

	fmt.Printf("Alice shared secret : %v\n", bob.X3DH(alice))
	fmt.Printf("Bob shared secret   : %v\n", alice.X3DH(bob))

	message := "Hello, world!"
	messageKey, nextChainKey := DeriveMessageKey(bob.ChainKey)
	encrypted, _, _ := Encrypt(message, messageKey)

	fmt.Printf("Encrypted: %v\n", encrypted)
	plaintext, _ := Decrypt(encrypted, messageKey)
	fmt.Printf("Decrypted: %v\n", plaintext)

	bob.ChainKey = nextChainKey
	alice.ChainKey = nextChainKey
}
