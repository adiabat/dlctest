// Copyright (c) 2015-2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"math/big"

	"github.com/adiabat/btcd/btcec"
	"github.com/adiabat/btcd/chaincfg/chainhash"
)

// scalarSize is the size of an encoded big endian scalar.
const scalarSize = 32

var (
	// bigZero is the big representation of zero.
	bigZero = new(big.Int).SetInt64(0)

	// ecTypeSecSchnorr is the ECDSA type for the chainec interface.
	ecTypeSecSchnorr = 2
)

// zeroArray zeroes the memory of a scalar array.
func zeroArray(a *[scalarSize]byte) {
	for i := 0; i < scalarSize; i++ {
		a[i] = 0x00
	}

	return
}

// zeroSlice zeroes the memory of a scalar byte slice.
func zeroSlice(s []byte) {
	for i := 0; i < scalarSize; i++ {
		s[i] = 0x00
	}

	return
}

// BigIntToEncodedBytes converts a big integer into its corresponding
// 32 byte little endian representation.
func BigIntToEncodedBytes(a *big.Int) *[32]byte {
	s := new([32]byte)
	if a == nil {
		return s
	}
	// Caveat: a can be longer than 32 bytes.
	aB := a.Bytes()

	// If we have a short byte string, expand
	// it so that it's long enough.
	aBLen := len(aB)
	if aBLen < scalarSize {
		diff := scalarSize - aBLen
		for i := 0; i < diff; i++ {
			aB = append([]byte{0x00}, aB...)
		}
	}

	for i := 0; i < scalarSize; i++ {
		s[i] = aB[i]
	}

	return s
}

// schnorrSign signs a Schnorr signature using a specified hash function
// and the given nonce, private key, message, and optional public nonce.
// CAVEAT: Lots of variable time algorithms using both the private key and
// k, which can expose the signer to constant time attacks. You have been
// warned! DO NOT use this algorithm where you might have the possibility
// of someone having EM field/cache/etc access.
// Memory management is also kind of sloppy and whether or not your keys
// or nonces can be found in memory later is likely a product of when the
// garbage collector runs.
// TODO Use field elements with constant time algorithms to prevent said
// attacks.
// This is identical to the Schnorr signature function found in libsecp256k1:
// https://github.com/bitcoin/secp256k1/tree/master/src/modules/schnorr
func RSign(curve *btcec.KoblitzCurve,
	msg []byte, ps []byte, k []byte) (*big.Int, error) {

	if len(msg) != scalarSize {
		str := fmt.Errorf("wrong size for message (got %v, want %v)",
			len(msg), scalarSize)
		return nil, str
	}

	if len(ps) != scalarSize {
		str := fmt.Errorf("wrong size for privkey (got %v, want %v)",
			len(ps), scalarSize)
		return nil, str
	}
	if len(k) != scalarSize {
		str := fmt.Errorf("wrong size for nonce k (got %v, want %v)",
			len(k), scalarSize)
		return nil, str
	}

	psBig := new(big.Int).SetBytes(ps)
	bigK := new(big.Int).SetBytes(k)

	if psBig.Cmp(bigZero) == 0 {
		str := fmt.Errorf("secret scalar is zero")
		return nil, str
	}
	if psBig.Cmp(curve.N) >= 0 {
		str := fmt.Errorf("secret scalar is out of bounds")
		return nil, str
	}
	if bigK.Cmp(bigZero) == 0 {
		str := fmt.Errorf("k scalar is zero")
		return nil, str
	}
	if bigK.Cmp(curve.N) >= 0 {
		str := fmt.Errorf("k scalar is out of bounds")
		return nil, str
	}

	// R = kG
	var Rpx, Rpy *big.Int
	Rpx, Rpy = curve.ScalarBaseMult(k)

	// Check if the field element that would be represented by Y is odd.
	// If it is, just keep k in the group order.
	if Rpy.Bit(0) == 1 {
		bigK.Mod(bigK, curve.N)
		bigK.Sub(curve.N, bigK)
	}

	// h = Hash(r || m)
	Rpxb := BigIntToEncodedBytes(Rpx)
	hashInput := make([]byte, 0, scalarSize*2)
	hashInput = append(hashInput, Rpxb[:]...)
	hashInput = append(hashInput, msg...)
	h := chainhash.HashB(hashInput)
	hBig := new(big.Int).SetBytes(h)

	// If the hash ends up larger than the order of the curve, abort.
	if hBig.Cmp(curve.N) >= 0 {
		str := fmt.Errorf("hash of (R || m) too big")
		return nil, str
	}

	// s = k - hx
	// TODO Speed this up a bunch by using field elements, not
	// big ints. That we multiply the private scalar using big
	// ints is also probably bad because we can only assume the
	// math isn't in constant time, thus opening us up to side
	// channel attacks. Using a constant time field element
	// implementation will fix this.
	sBig := new(big.Int)
	sBig.Mul(hBig, psBig)
	sBig.Sub(bigK, sBig)
	sBig.Mod(sBig, curve.N)

	if sBig.Cmp(bigZero) == 0 {
		str := fmt.Errorf("sig s %v is zero", sBig)
		return nil, str
	}

	// Zero out the private key and nonce when we're done with it.
	bigK.SetInt64(0)
	zeroSlice(k)
	psBig.SetInt64(0)
	zeroSlice(ps)

	return sBig, nil
}

// schnorrVerify is the internal function for verification of a secp256k1
// Schnorr signature. A secure hash function may be passed for the calculation
// of r.
// This is identical to the Schnorr verification function found in libsecp256k1:
// https://github.com/bitcoin/secp256k1/tree/master/src/modules/schnorr
/*
func schnorrVerify(curve *btcec.KoblitzCurve, sig []byte,
	pubkey *btcec.PublicKey, msg []byte, hashFunc func([]byte) []byte) (bool,
	error) {
	if len(msg) != scalarSize {
		str := fmt.Sprintf("wrong size for message (got %v, want %v)",
			len(msg), scalarSize)
		return false, schnorrError(ErrBadInputSize, str)
	}

	if len(sig) != SignatureSize {
		str := fmt.Sprintf("wrong size for signature (got %v, want %v)",
			len(sig), SignatureSize)
		return false, schnorrError(ErrBadInputSize, str)
	}
	if pubkey == nil {
		str := fmt.Sprintf("nil pubkey")
		return false, schnorrError(ErrInputValue, str)
	}

	if !curve.IsOnCurve(pubkey.GetX(), pubkey.GetY()) {
		str := fmt.Sprintf("pubkey point is not on curve")
		return false, schnorrError(ErrPointNotOnCurve, str)
	}

	sigR := sig[:32]
	sigS := sig[32:]
	sigRCopy := make([]byte, scalarSize, scalarSize)
	copy(sigRCopy, sigR)
	toHash := append(sigRCopy, msg...)
	h := hashFunc(toHash)
	hBig := new(big.Int).SetBytes(h)

	// If the hash ends up larger than the order of the curve, abort.
	// Same thing for hash == 0 (as unlikely as that is...).
	if hBig.Cmp(curve.N) >= 0 {
		str := fmt.Sprintf("hash of (R || m) too big")
		return false, schnorrError(ErrSchnorrHashValue, str)
	}
	if hBig.Cmp(bigZero) == 0 {
		str := fmt.Sprintf("hash of (R || m) is zero value")
		return false, schnorrError(ErrSchnorrHashValue, str)
	}

	// Convert s to big int.
	sBig := EncodedBytesToBigInt(copyBytes(sigS))

	// We also can't have s greater than the order of the curve.
	if sBig.Cmp(curve.N) >= 0 {
		str := fmt.Sprintf("s value is too big")
		return false, schnorrError(ErrInputValue, str)
	}

	// r can't be larger than the curve prime.
	rBig := EncodedBytesToBigInt(copyBytes(sigR))
	if rBig.Cmp(curve.P) == 1 {
		str := fmt.Sprintf("given R was greater than curve prime")
		return false, schnorrError(ErrBadSigRNotOnCurve, str)
	}

	// r' = hQ + sG
	lx, ly := curve.ScalarMult(pubkey.GetX(), pubkey.GetY(), h)
	rx, ry := curve.ScalarBaseMult(sigS)
	rlx, rly := curve.Add(lx, ly, rx, ry)

	if rly.Bit(0) == 1 {
		str := fmt.Sprintf("calculated R y-value was odd")
		return false, schnorrError(ErrBadSigRYValue, str)
	}
	if !curve.IsOnCurve(rlx, rly) {
		str := fmt.Sprintf("calculated R point was not on curve")
		return false, schnorrError(ErrBadSigRNotOnCurve, str)
	}
	rlxB := BigIntToEncodedBytes(rlx)

	// r == r' --> valid signature
	if !bytes.Equal(sigR, rlxB[:]) {
		str := fmt.Sprintf("calculated R point was not given R")
		return false, schnorrError(ErrUnequalRValues, str)
	}

	return true, nil
}
*/
