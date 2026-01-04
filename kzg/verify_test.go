package kzg

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestKZGVerify(t *testing.T) {
	// SRS
	srs := GenerateSRS(4)

	// f(X) = 3 + 2X + X²
	coeffs := make([]fr.Element, 3)
	coeffs[0].SetUint64(3)
	coeffs[1].SetUint64(2)
	coeffs[2].SetUint64(1)
	poly := &Polynomial{Coefficients: coeffs}

	// Commit
	C := Commit(poly, srs)

	// Evaluation point
	var z fr.Element
	z.SetUint64(7)

	// Proof
	y, proof := Open(poly, srs, z.BigInt(new(big.Int)))

	ok := Verify(
		C,
		z.BigInt(new(big.Int)),
		y,
		proof,
		srs,
	)

	if !ok {
		t.Fatal("KZG verification failed (expected success)")
	}
}
