package example

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func NewKey() *btcec.PrivateKey {
	prvkey, err := btcec.NewPrivateKey()
	if err != nil {
		panic(err)
	}
	return prvkey
}

func FromKey(rawHex string) *btcec.PrivateKey {
	raw, err := hex.DecodeString(rawHex)
	if err != nil {
		panic(err)
	}
	prvkey, _ := btcec.PrivKeyFromBytes(raw)
	return prvkey
}

func Keygen() {
	prvkey := NewKey()

	rawPrvKey := prvkey.Serialize()

	// Parse raw private key
	_, _ = btcec.PrivKeyFromBytes(rawPrvKey)

	fmt.Println("Private key", hex.EncodeToString(rawPrvKey))

	// 33 bytes
	fmt.Println("Compressed Public key", prvkey.PubKey().SerializeCompressed())
	// 65 bytes
	fmt.Println("Uncompressed Public key", prvkey.PubKey().SerializeUncompressed())

	// 32 bytes
	fmt.Println("Schnorr(BIP-340) Public key",
		hex.EncodeToString(schnorr.SerializePubKey(prvkey.PubKey())))
}
