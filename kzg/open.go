package kzg

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

func Open(poly *Polynomial, srs *SRS, z *big.Int) (y *big.Int, proof bls12381.G1Affine) {
	y = poly.Evaluate(z)

	q := ComputeQuotient(poly, z, y)
	proof = Commit(q, srs)

	return
}
