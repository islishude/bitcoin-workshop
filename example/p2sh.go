package example

import (
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func Pay2ScriptHashTx() *wire.MsgTx {
	var regtest = &chaincfg.RegressionNetParams

	alice, bob, cario := NewKey(), NewKey(), NewKey()

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

	address, err := btcutil.NewAddressScriptHash(redeemScript, regtest)
	if err != nil {
		panic(err)
	}

	newtx := wire.NewMsgTx(2)

	{
		// txout to the address
		{
			output, err := txscript.PayToAddrScript(address)
			if err != nil {
				panic(err)
			}
			txout := wire.NewTxOut(1e4, output)
			newtx.AddTxOut(txout)
		}

		// txin
		{
			const txIdx = 0
			prevTxid, err := chainhash.NewHashFromStr("702f4a9215e537bcadc4c9d470dc49ff7a987b5a770ae2653244b773886c5315")
			if err != nil {
				panic(err)
			}
			txin := wire.NewTxIn(wire.NewOutPoint(prevTxid, 1), nil, nil)
			newtx.AddTxIn(txin)

			aliceSig, err := txscript.RawTxInSignature(newtx, txIdx, redeemScript, txscript.SigHashAll, alice)
			if err != nil {
				panic(err)
			}

			bobSig, err := txscript.RawTxInSignature(newtx, txIdx, redeemScript, txscript.SigHashAll, bob)
			if err != nil {
				panic(err)
			}

			signatureScript, err := txscript.NewScriptBuilder().
				AddOp(txscript.OP_0).
				AddData(aliceSig).
				AddData(bobSig).
				AddData(redeemScript).Script()
			if err != nil {
				panic(err)
			}
			newtx.TxIn[0].SignatureScript = signatureScript
		}
	}
	return newtx
}
