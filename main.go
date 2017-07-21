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

	privBytes := chainhash.HashB([]byte("private key..."))

	priv, pub := btcec.PrivKeyFromBytes(c, privBytes)

	//	pubkey := priv.PubKey()

	kBytes := chainhash.HashB([]byte("this is k"))
	k, r := btcec.PrivKeyFromBytes(c, kBytes)

	m := chainhash.HashB([]byte("message to sign"))

	s, err :=
		RSign(c, m, priv.Serialize(), k.Serialize())
	if err != nil {
		panic(err)
	}

	ssg := new(btcec.PublicKey)
	ssg.X, ssg.Y = c.ScalarBaseMult(s.Bytes())

	fmt.Printf("r:%x\ns:%s\nsg:%x\n", k.PubKey().SerializeCompressed(),
		s.String(), ssg.SerializeCompressed())

	sg, err := SGpredict(c, m, pub, r)
	if err != nil {
		panic(err)
	}

	fmt.Printf("sg:%x\n", sg.SerializeCompressed())

}
