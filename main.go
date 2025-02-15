package main

import (
	"fmt"
	"log"
)

func main() {
	bob := NewParticipant()
	alice := NewParticipant()

	fmt.Printf("Alice shared secret : %v\n", bob.X3DH(alice))
	fmt.Printf("Bob shared secret   : %v\n", alice.X3DH(bob))

	skippedKeys := make(map[int][]byte)
	skippedMessages := make(map[int]string)
	messageCounter := 0

	aliceMessages := []string{"Hello, Bob!", "Are you there?", "I have something important to tell you."}

	for _, message := range aliceMessages {
		messageKey, nextChainKey := DeriveMessageKey(alice.ChainKey) // FIX: Use Alice's ChainKey
		encrypted, _, _ := Encrypt(message, messageKey)

		fmt.Printf("Encrypted: %v\n", encrypted)

		skippedKeys[messageCounter] = messageKey
		skippedMessages[messageCounter] = encrypted
		messageCounter++

		alice.ChainKey = nextChainKey
	}

	bobMessage := "Hey Alice! Sorry, I just saw your messages."

	// Bob decrypts messages before replying
	for i := 0; i < messageCounter; i++ {
		messageKey, nextChainKey := DeriveMessageKey(bob.ChainKey)
		plaintext, err := Decrypt(skippedMessages[i], messageKey)

		if err != nil {
			log.Fatalf("Decryption failed for message %d: %v\n", i, err)
		}

		fmt.Printf("Decrypted: %v\n", plaintext)

		bob.ChainKey = nextChainKey

		delete(skippedKeys, i)
		delete(skippedMessages, i)
	}

	bobMessageKey, bobNextChainKey := DeriveMessageKey(bob.ChainKey)
	encryptedReply, _, _ := Encrypt(bobMessage, bobMessageKey)
	fmt.Printf("Encrypted: %v\n", encryptedReply[4:])

	aliceMessageKey, aliceNextChainKey := DeriveMessageKey(alice.ChainKey)
	decryptedReply, err := Decrypt(encryptedReply, aliceMessageKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Decrypted: %v\n", decryptedReply)

	bob.ChainKey = bobNextChainKey
	alice.ChainKey = aliceNextChainKey
}
