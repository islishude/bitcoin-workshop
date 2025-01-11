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

func Pay2ScriptHashTx(netwk *chaincfg.Params, alice, bob, cario *btcec.PrivateKey,
	prevTxHash *chainhash.Hash, prevTxOut uint32, prevAmountSat, fee int64) *wire.MsgTx {
	redeemScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_2).
		AddData(alice.PubKey().SerializeUncompressed()).
		AddData(bob.PubKey().SerializeUncompressed()).
		AddData(cario.PubKey().SerializeUncompressed()).
		AddOp(txscript.OP_3).
		AddOp(txscript.OP_CHECKMULTISIG).
		Script()

	if err != nil {
		panic(err)
	}

	address, err := btcutil.NewAddressScriptHash(redeemScript, netwk)
	if err != nil {
		panic(err)
	}
	fmt.Println("P2SH address:", address)

	newtx := wire.NewMsgTx(2)

	// txout to the address
	{
		output, err := txscript.PayToAddrScript(address)
		if err != nil {
			panic(err)
		}
		txout := wire.NewTxOut(prevAmountSat-fee, output)
		newtx.AddTxOut(txout)
	}

	// txin
	{
		txin := wire.NewTxIn(wire.NewOutPoint(prevTxHash, prevTxOut), nil, nil)
		newtx.AddTxIn(txin)
	}

	// sign
	for txIdx, txIn := range newtx.TxIn {
		aliceSig, err := txscript.RawTxInSignature(newtx, txIdx, redeemScript, txscript.SigHashAll, alice)
		if err != nil {
			panic(err)
		}

		bobSig, err := txscript.RawTxInSignature(newtx, txIdx, redeemScript, txscript.SigHashAll, bob)
		if err != nil {
			panic(err)
		}

		txIn.SignatureScript, err = txscript.NewScriptBuilder().
			AddOp(txscript.OP_0).
			AddData(aliceSig).
			AddData(bobSig).
			AddData(redeemScript).Script()
		if err != nil {
			panic(err)
		}
	}

	return newtx
}
