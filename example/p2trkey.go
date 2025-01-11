package example

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func Pay2TaprootByKeyPathTx(netwk *chaincfg.Params, prvkey *btcec.PrivateKey,
	prevTxid *chainhash.Hash, prevPkScript []byte, prevTxout int, prevAmountSat, curAmountSat int64) *wire.MsgTx {
	// We use bip68 here
	pubKey := txscript.ComputeTaprootKeyNoScript(prvkey.PubKey())
	address, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(pubKey), netwk)
	if err != nil {
		panic(err)
	}
	fmt.Println("P2TR Address:", address)

	newtx := wire.NewMsgTx(2)
	// txout
	{
		output, err := txscript.PayToAddrScript(address)
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
	}

	// sign
	for txIdx, txin := range newtx.TxIn {
		sigHashes := txscript.NewTxSigHashes(newtx,
			txscript.NewCannedPrevOutputFetcher(prevPkScript, prevAmountSat))

		txin.Witness, err = txscript.TaprootWitnessSignature(
			newtx,
			sigHashes,
			txIdx,
			prevAmountSat,
			prevPkScript,
			txscript.SigHashDefault,
			prvkey,
		)
		if err != nil {
			panic(err)
		}
	}

	return newtx
}
