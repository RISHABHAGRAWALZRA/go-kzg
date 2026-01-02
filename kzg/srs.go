package kzg

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type SRS struct {
	G1 []bls12381.G1Affine
	G2 []bls12381.G2Affine
}

// In a real implementation, the SRS would be generated securely.
// Here we use a placeholder implementation for demonstration purposes.
func GenerateSRS(maxDegree int) *SRS {

	var s fr.Element
	s.SetRandom() // TOXIC WASTE ☢️

	_, _, g1Gen, g2Gen := bls12381.Generators()
	srs := &SRS{
		G1: make([]bls12381.G1Affine, maxDegree+1),
		G2: make([]bls12381.G2Affine, 2), // Typically G2 has only two elements for KZG
	}

	var power fr.Element
	power.SetOne()

	for i := 0; i <= maxDegree; i++ {
		srs.G1[i].ScalarMultiplication(&g1Gen, power.BigInt(new(big.Int)))
		power.Mul(&power, &s)
	}

	srs.G2[0] = g2Gen
	srs.G2[1].ScalarMultiplication(&g2Gen, s.BigInt(new(big.Int)))

	return srs
}
