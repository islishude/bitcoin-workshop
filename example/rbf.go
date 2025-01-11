package example

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki
func ReplaceByFee(netwk *chaincfg.Params, prvkey *btcec.PrivateKey, prevTxHash *chainhash.Hash, prevTxOut uint32, prevAmount int64) {
	pubkeyHash := btcutil.Hash160(prvkey.PubKey().SerializeCompressed())
	address, err := btcutil.NewAddressPubKeyHash(pubkeyHash, netwk)
	if err != nil {
		panic(err)
	}
	fmt.Println("p2pkh address:", address)

	subScript, err := txscript.PayToAddrScript(address)
	if err != nil {
		panic(err)
	}

	newtx := wire.NewMsgTx(2)

	const fee1 = 1e3

	// txout to the address
	{
		txout := wire.NewTxOut(prevAmount-fee1, subScript)
		newtx.AddTxOut(txout)
	}

	// txin
	{
		txin := wire.NewTxIn(wire.NewOutPoint(prevTxHash, prevTxOut), nil, nil)
		txin.Sequence = wire.MaxTxInSequenceNum - 2
		newtx.AddTxIn(txin)
	}

	// sign
	for txIdx, txIn := range newtx.TxIn {
		sig, err := txscript.SignatureScript(newtx, txIdx, subScript, txscript.SigHashAll, prvkey, true)
		if err != nil {
			panic(err)
		}
		txIn.SignatureScript = sig
	}

	// replace by fee
	const fee2 = fee1 + 100
	for i := range newtx.TxOut {
		newtx.TxOut[i] = wire.NewTxOut(prevAmount-fee2, subScript)
	}

	// sign for the rbf
	for txIdx, txIn := range newtx.TxIn {
		sig, err := txscript.SignatureScript(newtx, txIdx, subScript, txscript.SigHashAll, prvkey, true)
		if err != nil {
			panic(err)
		}
		txIn.SignatureScript = sig
	}
}
