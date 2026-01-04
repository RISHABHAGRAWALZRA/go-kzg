package kzg

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type Polynomial struct {
	Coefficients []fr.Element // f(x) = c0 + c1 X + c2 X^2 + ... + cn X^n
}

// Evaluate computes the value of the polynomial at a given point x.
// F(z) in KZG opening or blob cell value in EIP4844 or Leaf value in verkle tree.
func (p *Polynomial) Evaluate2(x fr.Element) fr.Element {
	result := fr.Element{}
	result.SetZero()

	power := fr.Element{}
	power.SetOne()

	for _, coeff := range p.Coefficients {
		var temp fr.Element
		temp.Mul(&coeff, &power)
		result.Add(&result, &temp)
		power.Mul(&power, &x)
	}

	return result
}

func (p *Polynomial) Evaluate(z *big.Int) *big.Int {
	result := new(big.Int).SetInt64(0)
	mod := fr.Modulus()

	for i := len(p.Coefficients) - 1; i >= 0; i-- {
		result.Mul(result, z)
		result.Mod(result, mod)
		result.Add(result, p.Coefficients[i].BigInt(new(big.Int)))
		result.Mod(result, mod)
	}
	return result
}

func (p *Polynomial) Substract(other *Polynomial) *Polynomial {
	maxLen := len(p.Coefficients)
	if len(other.Coefficients) > maxLen {
		maxLen = len(other.Coefficients)
	}

	resultCoeffs := make([]fr.Element, maxLen)
	for i := 0; i < maxLen; i++ {
		if i < len(p.Coefficients) {
			resultCoeffs[i].Set(&p.Coefficients[i])
		}
		if i < len(other.Coefficients) {
			resultCoeffs[i].Sub(&resultCoeffs[i], &other.Coefficients[i])
		}
	}
	return &Polynomial{Coefficients: resultCoeffs}

}

// q(X) = f(X) - f(z) / (X - z)
func (p *Polynomial) DivideLinear(z fr.Element) *Polynomial {
	n := len(p.Coefficients)
	if n <= 1 {
		panic("degree too small")
	}

	q := make([]fr.Element, n-1)
	var rem fr.Element
	rem.SetZero()

	for i := n - 1; i > 0; i-- {
		q[i-1].Add(&p.Coefficients[i], &rem)
		rem.Mul(&q[i-1], &z)
		rem.Neg(&rem)
	}

	return &Polynomial{Coefficients: q}
}

func ComputeQuotient(poly *Polynomial, z, y *big.Int) *Polynomial {
	n := len(poly.Coefficients)
	mod := fr.Modulus()

	q := make([]fr.Element, n-1)

	var acc big.Int
	acc.Set(poly.Coefficients[n-1].BigInt(new(big.Int)))

	for i := n - 2; i >= 0; i-- {
		q[i].SetBigInt(&acc)
		acc.Mul(&acc, z)
		acc.Add(&acc, poly.Coefficients[i].BigInt(new(big.Int)))
		acc.Mod(&acc, mod)
	}

	// subtract y at the end (guaranteed zero remainder)
	acc.Sub(&acc, y)
	acc.Mod(&acc, mod)

	if acc.Sign() != 0 {
		panic("non-zero remainder: invalid opening")
	}

	return &Polynomial{Coefficients: q}
}
