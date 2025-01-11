package example

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func Pay2TaprootByKeyPathAddr(prvkey *btcec.PrivateKey, net *chaincfg.Params) btcutil.Address {
	// We use bip68 here
	pubKey := txscript.ComputeTaprootKeyNoScript(prvkey.PubKey())

	witnessProg := schnorr.SerializePubKey(pubKey)

	addr, err := btcutil.NewAddressTaproot(witnessProg, net)
	if err != nil {
		panic(err)
	}

	return addr
}

func Pay2TaprootByKeyPathTx(prvkey *btcec.PrivateKey,
	prevTxid *chainhash.Hash, prevPkScript []byte, prevTxout int, prevAmountSat, curAmountSat int64) *wire.MsgTx {
	newtx := wire.NewMsgTx(2)

	// txout to p2pr
	{
		pubKey := txscript.ComputeTaprootKeyNoScript(prvkey.PubKey())

		output, err := txscript.NewScriptBuilder().
			AddOp(txscript.OP_1).
			AddData(schnorr.SerializePubKey(pubKey)).
			Script()
		if err != nil {
			panic(err)
		}
		txout := wire.NewTxOut(curAmountSat, output)
		newtx.AddTxOut(txout)
	}

	// txin, spend p2pr output
	{
		txin := wire.NewTxIn(wire.NewOutPoint(prevTxid, uint32(prevTxout)), nil, nil)
		newtx.AddTxIn(txin)

		sigHashes := txscript.NewTxSigHashes(newtx,
			txscript.NewCannedPrevOutputFetcher(prevPkScript, prevAmountSat))

		witSig, err := txscript.TaprootWitnessSignature(
			newtx,
			sigHashes,
			0, // idx, **the current tx input index that we want to sign**
			prevAmountSat,
			prevPkScript,
			txscript.SigHashDefault,
			prvkey,
		)
		if err != nil {
			panic(err)
		}
		txin.Witness = witSig
	}

	return newtx
}
