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
func ReplaceByFee(netwk *chaincfg.Params, prvkey *btcec.PrivateKey, prevTxHash *chainhash.Hash, prevTxOut uint32, prevAmount, fee int64) {
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

	// txout to the address
	{
		value := prevAmount - fee
		if value < 546 {
			panic("the amount is too small")
		}
		txout := wire.NewTxOut(prevAmount-fee, subScript)
		newtx.AddTxOut(txout)
	}

	// txin
	{
		txin := wire.NewTxIn(wire.NewOutPoint(prevTxHash, prevTxOut), nil, nil)
		// if the 0xfffffffe > nSequence > 0x80000000, the tx is replaceable
		// the highest bit must be 1 to signal that it doesn't use (bip68)[https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki]
		txin.Sequence = 0xfffffff0
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

	// Increase the sequence number, but it's optional
	newtx.TxIn[0].Sequence += 1

	// the default minRelayFeeRate is 1 satoshi per byte
	minRelayFeeRate := int64(1)
	minRelayFee := int64(newtx.SerializeSize()) * minRelayFeeRate

	// replace by fee
	fee2 := fee + minRelayFee
	if prevAmount-fee2 < 546 {
		panic("the amount is too small")
	}
	newtx.TxOut[0] = wire.NewTxOut(prevAmount-fee2, subScript)

	// sign for the rbf
	for txIdx, txIn := range newtx.TxIn {
		sig, err := txscript.SignatureScript(newtx, txIdx, subScript, txscript.SigHashAll, prvkey, true)
		if err != nil {
			panic(err)
		}
		txIn.SignatureScript = sig
	}
}
