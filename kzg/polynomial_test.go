package kzg

import (
	"log"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestPolynomialDivision(t *testing.T) {
	var f Polynomial
	f.Coefficients = make([]fr.Element, 3)

	f.Coefficients[0].SetUint64(3)
	f.Coefficients[1].SetUint64(2)
	f.Coefficients[2].SetUint64(1)

	var z fr.Element
	z.SetUint64(5)

	v := fr.NewElement(39)
	y := f.Evaluate(z)
	log.Println("Result of evaluate", y.Uint64())
	if !y.Equal(&v) {
		t.Fatalf("unexpected evaluation result")
	}
}
