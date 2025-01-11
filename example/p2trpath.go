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

// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
var rawNothingInMySlee, _ = hex.DecodeString("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
var NothingInMySleeve, _ = schnorr.ParsePubKey(rawNothingInMySlee)

func PayToTaprootByPath(netwk *chaincfg.Params, alice, bob, cario, god *btcec.PrivateKey,
	prevTxHash *chainhash.Hash, prevTxout uint32, prevAmountSat, fee int64) *wire.MsgTx {

	// https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki#rationale
	// Using a single OP_CHECKSIGADD-based script A CHECKMULTISIG script
	// m <pubkey_1> ... <pubkey_n> n CHECKMULTISIG with witness 0 <signature_1> ... <signature_m>
	// can be rewritten as script
	// <pubkey_1> CHECKSIG <pubkey_2> CHECKSIGADD ... <pubkey_n> CHECKSIGADD m NUMEQUAL
	// with witness
	// <w_n> ... <w_1>.
	// Every witness element w_i is either a signature corresponding to pubkey_i or an empty vector.

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

	var outputKey *btcec.PublicKey
	if god == nil {
		outputKey = txscript.ComputeTaprootOutputKey(NothingInMySleeve, rootHash[:])
	} else {
		outputKey = txscript.ComputeTaprootOutputKey(god.PubKey(), rootHash[:])
	}

	address, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(outputKey), netwk)
	if err != nil {
		panic(err)
	}
	fmt.Println("P2TR Address:", address)

	newtx := wire.NewMsgTx(2)
	// add txin
	{
		txin := wire.NewTxIn(wire.NewOutPoint(prevTxHash, prevTxout), nil, nil)
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

	for txIdx, txin := range newtx.TxIn {
		prevPkScript, _ := txscript.PayToAddrScript(address)
		sigHashes := txscript.NewTxSigHashes(newtx,
			txscript.NewCannedPrevOutputFetcher(prevPkScript, prevAmountSat))

		if god != nil {
			// pay with key path
			sig, err := txscript.RawTxInTaprootSignature(
				newtx,
				sigHashes,
				txIdx,
				prevAmountSat,
				prevPkScript,
				rootHash[:],
				txscript.SigHashDefault,
				god,
			)
			if err != nil {
				panic(err)
			}
			txin.Witness = wire.TxWitness{sig}
		} else {
			// pay with script path
			aliceSig, err := txscript.RawTxInTapscriptSignature(newtx, sigHashes, txIdx, prevAmountSat,
				prevPkScript, leaf1, txscript.SigHashDefault, alice)
			if err != nil {
				panic(err)
			}

			carioSig, err := txscript.RawTxInTapscriptSignature(newtx, sigHashes, txIdx, prevAmountSat,
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

			txin.Witness = wire.TxWitness{carioSig, []byte{}, aliceSig, script1, controlBlockWitness}
		}
	}

	return newtx
}
