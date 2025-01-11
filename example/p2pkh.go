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

func Pay2PubkeyHash(netwk *chaincfg.Params, prvkey *btcec.PrivateKey,
	prevTxHash *chainhash.Hash, prevTxOut uint32, prevAmount, fee int64) *wire.MsgTx {

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
		txout := wire.NewTxOut(prevAmount-fee, subScript)
		newtx.AddTxOut(txout)
	}

	// txin
	{
		txin := wire.NewTxIn(wire.NewOutPoint(prevTxHash, prevTxOut), nil, nil)
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
	return newtx
}
