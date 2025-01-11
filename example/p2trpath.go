package example

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

var rawNothingInMySlee, _ = hex.DecodeString("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
var NothingInMySleeve, _ = schnorr.ParsePubKey(rawNothingInMySlee)

func PayToTaprootByPath(alice, bob, cario *btcec.PrivateKey, prevTxHash *chainhash.Hash) {
	var regtest = &chaincfg.RegressionNetParams

	script1, err := txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(alice.PubKey())).
		AddOp(txscript.OP_CHECKSIG).
		AddData(schnorr.SerializePubKey(bob.PubKey())).
		AddOp(txscript.OP_CHECKSIGADD).
		AddData(schnorr.SerializePubKey(cario.PubKey())).
		AddOp(txscript.OP_CHECKSIGADD).
		AddOp(txscript.OP_2).
		AddOp(txscript.OP_NUMEQUAL).
		Script()

	if err != nil {
		panic(err)
	}

	script2, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_RETURN).
		AddData([]byte("data")).Script()
	if err != nil {
		panic(err)
	}

	leaf1, leaf2 := txscript.NewBaseTapLeaf(script1), txscript.NewBaseTapLeaf(script2)
	scriptTree := txscript.AssembleTaprootScriptTree(leaf1, leaf2)
	rootHash := scriptTree.RootNode.TapHash()
	outputKey := txscript.ComputeTaprootOutputKey(NothingInMySleeve, rootHash[:])

	address, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(outputKey), regtest)
	if err != nil {
		panic(err)
	}

	fmt.Println("address", address)

	const prevTxout = 1
	const prevAmountSat = 1e8
	const fee = 1e3

	newtx := wire.NewMsgTx(2)
	// add txin
	{
		txin := wire.NewTxIn(wire.NewOutPoint(prevTxHash, uint32(prevTxout)), nil, nil)
		txin.Sequence = wire.MaxTxInSequenceNum - 5 // let it be replaceable
		newtx.AddTxIn(txin)
	}

	// add txout
	{
		output, err := txscript.PayToAddrScript(address)
		if err != nil {
			panic(err)
		}
		txout := wire.NewTxOut(prevAmountSat-fee, output)
		newtx.AddTxOut(txout)
	}

	// if you're not using the nothing-in-my-sleeve key, you can use the following code
	// the god key is the private key that can spend the taproot output
	// {
	// 	var i = 0
	// 	prevPkScript, _ := txscript.PayToAddrScript(address)
	// 	sigHashes := txscript.NewTxSigHashes(newtx,
	// 		txscript.NewCannedPrevOutputFetcher(prevPkScript, prevAmountSat))

	// 	sig, err := txscript.RawTxInTaprootSignature(
	// 		newtx,
	// 		sigHashes,
	// 		i,
	// 		prevAmountSat,
	// 		prevPkScript,
	// 		rootHash[:],
	// 		txscript.SigHashDefault,
	// 		god,
	// 	)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	newtx.TxIn[i].Witness = wire.TxWitness{sig}
	// }

	// pay with script path
	{
		var i = 0
		prevPkScript, err := txscript.PayToAddrScript(address)
		if err != nil {
			panic(err)
		}

		sigHashes := txscript.NewTxSigHashes(newtx,
			txscript.NewCannedPrevOutputFetcher(prevPkScript, prevAmountSat))

		aliceSig, err := txscript.RawTxInTapscriptSignature(newtx, sigHashes, i, prevAmountSat,
			prevPkScript, leaf1, txscript.SigHashDefault, alice)
		if err != nil {
			panic(err)
		}

		carioSig, err := txscript.RawTxInTapscriptSignature(newtx, sigHashes, i, prevAmountSat,
			prevPkScript, leaf1, txscript.SigHashDefault, cario)
		if err != nil {
			panic(err)
		}

		// sign
		controlBlock := scriptTree.LeafMerkleProofs[0].ToControlBlock(NothingInMySleeve)
		controlBlockWitness, err := controlBlock.ToBytes()
		if err != nil {
			panic(err)
		}

		newtx.TxIn[i].Witness = wire.TxWitness{carioSig, []byte{}, aliceSig, script1, controlBlockWitness}
	}
}
