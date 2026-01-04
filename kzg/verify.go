package kzg

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

func Verify(
	C bls12381.G1Affine,
	z, y *big.Int,
	proof bls12381.G1Affine,
	srs *SRS,
) bool {

	// Compute C - [y]₁
	var yG1 bls12381.G1Affine
	yG1.ScalarMultiplicationBase(y)
	var lhsG1 bls12381.G1Jac
	lhsG1.FromAffine(&C)
	var yJac bls12381.G1Jac
	yJac.FromAffine(&yG1)
	yJac.Neg(&yJac)
	lhsG1.AddAssign(&yJac)
	var lhs bls12381.G1Affine
	lhs.FromJacobian(&lhsG1)

	// Pairing equation is: e(C - [y]₁, G2) = e(proof, [s - z]₂)
	// This is equivalent to: e(C - [y]₁, G2) * e(proof, [z - s]₂) = 1
	// Where [z - s]₂ = [z]₂ - [s]₂ = -([s]₂ - [z]₂) = -[s - z]₂

	// So we need to compute [z - s]₂ = [z]₂ - [s]₂
	var zG2ForPairing bls12381.G2Affine
	zG2ForPairing.ScalarMultiplicationBase(z)
	var zG2JacForPairing bls12381.G2Jac
	zG2JacForPairing.FromAffine(&zG2ForPairing)

	var sG2ForPairing bls12381.G2Jac
	sG2ForPairing.FromAffine(&srs.G2[1])
	sG2ForPairing.Neg(&sG2ForPairing)          // -[s]₂
	sG2ForPairing.AddAssign(&zG2JacForPairing) // + [z]₂

	var zMinusSG2Pairing bls12381.G2Affine
	zMinusSG2Pairing.FromJacobian(&sG2ForPairing)

	// Check: e(C - [y]₁, G2) * e(proof, [z - s]₂) = 1
	result, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{lhs, proof},
		[]bls12381.G2Affine{srs.G2[0], zMinusSG2Pairing},
	)

	if err != nil {
		return false
	}

	return result
}
