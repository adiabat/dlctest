package main

import (
	"fmt"

	"github.com/adiabat/btcd/btcec"
	"github.com/adiabat/btcd/chaincfg/chainhash"
)

//func SchnorrSign(curve *secp256k1.KoblitzCurve, msg []byte, ps []byte, k []byte,
//	pubNonceX *big.Int, pubNonceY *big.Int,
//	hashFunc func([]byte) []byte) (*Signature, error) {

func main() {
	c := btcec.S256()

	//	privBytes := chainhash.HashB([]byte("private key"))

	priv, _ := btcec.PrivKeyFromBytes(c, []byte("private key"))

	//	pubkey := priv.PubKey()

	k, _ := btcec.PrivKeyFromBytes(c, []byte("this is k"))

	m := chainhash.HashB([]byte("message to sign"))

	s, err :=
		RSign(c, m, priv.Serialize(), k.Serialize())
	if err != nil {
		panic(err)
	}
	fmt.Printf("r:%x\ns:%s\n", k.PubKey().SerializeCompressed(),
		s.String())

}

//func guessS
