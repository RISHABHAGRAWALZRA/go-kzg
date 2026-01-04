package kzg

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

func Commit(poly *Polynomial, srs *SRS) bls12381.G1Affine {
	if len(poly.Coefficients) > len(srs.G1) {
		panic("polynomial degree exceeds SRS size")
	}

	var acc bls12381.G1Jac
	acc = bls12381.G1Jac{} // point at infinity

	for i, coeff := range poly.Coefficients {
		var tmp bls12381.G1Jac
		tmp.FromAffine(&srs.G1[i])
		tmp.ScalarMultiplication(&tmp, coeff.BigInt(new(big.Int)))
		acc.AddAssign(&tmp)
	}

	var result bls12381.G1Affine
	result.FromJacobian(&acc)
	return result
}
