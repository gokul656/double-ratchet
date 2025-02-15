# Double Ratchet Algorithm Implementation in Go

This repository provides a Go implementation of the **Double Ratchet Algorithm**, enabling two parties to exchange encrypted messages based on a shared secret key. This algorithm ensures that each message is encrypted with a unique key, providing forward secrecy and self-healing properties in secure communications.

## Overview

The **Double Ratchet Algorithm** is a cryptographic protocol that combines:

- **Symmetric-key ratchet**: Updates keys for each message to ensure that past keys cannot be derived from future ones.
- **Diffie-Hellman ratchet**: Incorporates new Diffie-Hellman key exchanges to provide future secrecy, ensuring that even if current keys are compromised, future messages remain secure.

This combination allows for secure asynchronous messaging, where parties can send and receive messages without needing to be online simultaneously.

## Features

- **Forward Secrecy**: Each message has a unique encryption key, so compromising one key doesn't affect past messages.
- **Future Secrecy**: Regularly updated keys ensure that compromising current keys doesn't affect future messages.
- **Asynchronous Communication**: Parties can exchange messages without requiring simultaneous online presence.

## Running

To run this, use:

```bash
make run
```

## Implementation Details

- **Cryptographic Primitives**:
  - **Diffie-Hellman (DH)**: Utilizes Curve25519 for key exchanges.
  - **Key Derivation Function (KDF)**: Employs HMAC-based HKDF with SHA-256.
  - **Encryption**: Uses AES-256 in CTR mode combined with HMAC-SHA-256 for authenticated encryption.

- **Message Handling**:
  - Supports out-of-order message reception.
  - Limits the number of skipped messages to prevent resource exhaustion attacks.

## Todo

- Need to implement ECDHE_RSA for improved security

## References

- [Double Ratchet Algorithm Specification](https://signal.org/docs/specifications/doubleratchet/)
- [Wikipedia: Double Ratchet Algorithm](https://en.wikipedia.org/wiki/Double_Ratchet_Algorithm)
- [Nikos Filippakis: Implementing Signal’s Double Ratchet Algorithm](https://nfil.dev/coding/encryption/python/double-ratchet-example/)

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

*Note: This implementation is intended for educational purposes. For production use, ensure thorough security reviews and testing.*
