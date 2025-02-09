package main

import (
	"fmt"
	"math/big"
)

const (
	P = 23
	G = 9

	PKeyA = 4
	PKeyB = 3
)

func proof() {
	pubA := modExp(G, PKeyA, P) // Compute (G^PKeyA) % P
	pubB := modExp(G, PKeyB, P) // Compute (G^PKeyB) % P

	ka := modExp(pubB, PKeyA, P) // Compute (pubB^PKeyA) % P
	kb := modExp(pubA, PKeyB, P) // Compute (pubA^PKeyB) % P

	fmt.Printf("ka: %v\n", ka)
	fmt.Printf("kb: %v\n", kb)
}

func modExp(base, exp, mod int) int {
	b := big.NewInt(int64(base))
	e := big.NewInt(int64(exp))
	m := big.NewInt(int64(mod))
	result := new(big.Int).Exp(b, e, m) // Compute (base^exp) % mod using big.Int

	return int(result.Int64())
}
