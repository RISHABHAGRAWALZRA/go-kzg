package kzg

import "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

type Polynomial struct {
	Coefficients []fr.Element // f(x) = c0 + c1 X + c2 X^2 + ... + cn X^n
}

// Evaluate computes the value of the polynomial at a given point x.
// F(z) in KZG opening or blob cell value in EIP4844 or Leaf value in verkle tree.
func (p *Polynomial) Evaluate(x fr.Element) fr.Element {
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
