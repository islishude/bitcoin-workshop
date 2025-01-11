package example

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func CreateP2WSHMultiSigTx() *wire.MsgTx {
	var regtest = &chaincfg.RegressionNetParams

	alice, bob, cario := NewKey(), NewKey(), NewKey()

	redeemScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_2).
		AddData(alice.PubKey().SerializeCompressed()).
		AddData(bob.PubKey().SerializeCompressed()).
		AddData(cario.PubKey().SerializeCompressed()).
		AddOp(txscript.OP_3).
		AddOp(txscript.OP_CHECKMULTISIG).
		Script()

	if err != nil {
		panic(err)
	}

	newtx := wire.NewMsgTx(2)
	// add txin
	{
		// the current tx input index
		const prevTxout = 1
		prevTxid, err := chainhash.NewHashFromStr("fc137fe8d6678787912186b72616bd44c78077ec9b5fbbaa5338f991d426b392")
		if err != nil {
			panic(err)
		}

		txin := wire.NewTxIn(wire.NewOutPoint(prevTxid, uint32(prevTxout)), nil, nil)
		txin.Sequence = wire.MaxTxInSequenceNum - 5 // let it be replaceable
		newtx.AddTxIn(txin)
	}

	// add txout
	{
		scriptHash := sha256.Sum256(redeemScript)
		address, err := btcutil.NewAddressWitnessScriptHash(scriptHash[:], regtest)
		if err != nil {
			panic(err)
		}
		fmt.Println("P2WSH Address:", address)

		output, err := txscript.PayToAddrScript(address)
		if err != nil {
			panic(err)
		}
		txout := wire.NewTxOut(1e8-1e3, output)
		newtx.AddTxOut(txout)
	}

	// sign
	for txIdx, TxIn := range newtx.TxIn {
		const prevAmountSat = 1e8

		sigHashes := txscript.NewTxSigHashes(newtx,
			txscript.NewCannedPrevOutputFetcher(redeemScript, prevAmountSat))

		aliceSig, err := txscript.RawTxInWitnessSignature(newtx,
			sigHashes, txIdx, prevAmountSat, redeemScript, txscript.SigHashAll, alice)
		if err != nil {
			panic(err)
		}

		bobSig, err := txscript.RawTxInWitnessSignature(newtx,
			sigHashes, txIdx, prevAmountSat, redeemScript, txscript.SigHashAll, bob)
		if err != nil {
			panic(err)
		}

		// replace OP_0 with empty witness
		// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
		// A non-witness program (defined hereinafter) txin MUST be associated with an empty witness field, represented by a 0x00.
		TxIn.Witness = wire.TxWitness{[]byte{}, aliceSig, bobSig, redeemScript}
	}
	return newtx
}

func CreateBip112P2wsh(aliceKey, bobKey *btcec.PrivateKey, prevTxHash *chainhash.Hash, prevTxout uint32, prevAmountSat, fee int64) *wire.MsgTx {
	var regtest = &chaincfg.RegressionNetParams

	var cond1 [32]byte // commitment using timelock
	var cond2 [32]byte // commitment using multi-sig

	// time lock
	const blockLockNumber = 2 // <= 2 ** 16

	redeemScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_DUP).
		AddData(cond1[:]).
		AddOp(txscript.OP_EQUAL).
		AddOp(txscript.OP_IF).
		AddOp(txscript.OP_DROP).
		AddInt64(blockLockNumber).
		AddOp(txscript.OP_CHECKSEQUENCEVERIFY).
		AddOp(txscript.OP_DROP).
		AddData(bobKey.PubKey().SerializeCompressed()).
		AddOp(txscript.OP_CHECKSIG).
		AddOp(txscript.OP_ELSE).
		AddData(cond2[:]).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_2).
		AddData(aliceKey.PubKey().SerializeCompressed()).
		AddData(bobKey.PubKey().SerializeCompressed()).
		AddOp(txscript.OP_2).
		AddOp(txscript.OP_CHECKMULTISIG).
		AddOp(txscript.OP_ENDIF).
		Script()
	if err != nil {
		panic(err)
	}

	witnessProg := sha256.Sum256(redeemScript)
	address, err := btcutil.NewAddressWitnessScriptHash(witnessProg[:], regtest)
	if err != nil {
		panic(err)
	}
	fmt.Println("p2wsh address", address)

	prevPkScript, err := txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(witnessProg[:]).Script()
	if err != nil {
		panic(err)
	}
	fmt.Println("p2wsh pkScript", hex.EncodeToString(prevPkScript))

	newtx := wire.NewMsgTx(2)

	// txout to the internal tss group address
	{
		output, err := txscript.PayToAddrScript(address)
		if err != nil {
			panic(err)
		}
		txout := wire.NewTxOut(prevAmountSat-fee, output)
		newtx.AddTxOut(txout)
	}

	// txin using mulsig
	{
		const txIdx = 0
		txin := wire.NewTxIn(wire.NewOutPoint(prevTxHash, uint32(prevTxout)), nil, nil)
		newtx.AddTxIn(txin)

		sigHashes := txscript.NewTxSigHashes(newtx,
			txscript.NewCannedPrevOutputFetcher(prevPkScript, prevAmountSat))

		sig0, err := txscript.RawTxInWitnessSignature(
			newtx, sigHashes, txIdx,
			prevAmountSat, redeemScript,
			txscript.SigHashAll, aliceKey,
		)
		if err != nil {
			panic(err)
		}

		sig1, err := txscript.RawTxInWitnessSignature(
			newtx, sigHashes, txIdx,
			prevAmountSat,
			redeemScript, // the actual script to be signed
			txscript.SigHashAll, bobKey,
		)
		if err != nil {
			panic(err)
		}

		txin.Witness = wire.TxWitness{[]byte{}, sig0, sig1, cond2[:], redeemScript}
	}

	// txin using time lock
	// {
	// 	const txIdx = 0
	// 	txin := wire.NewTxIn(wire.NewOutPoint(prevTxHash, uint32(prevTxout)), nil, nil)
	// 	txin.Sequence = blockLockNumber
	// 	newtx.AddTxIn(txin)

	// 	sigHashes := txscript.NewTxSigHashes(newtx,
	// 		txscript.NewCannedPrevOutputFetcher(prevPkScript, prevAmountSat))

	// 	sig1, err := txscript.RawTxInWitnessSignature(
	// 		newtx, sigHashes, txIdx,
	// 		prevAmountSat,
	// 		redeemScript, // the actual script to be signed
	// 		txscript.SigHashAll, bobKey,
	// 	)
	// 	if err != nil {
	// 		panic(err)
	// 	}

	// 	txin.Witness = wire.TxWitness{sig1, cond1[:], redeemScript}
	// }

	return newtx
}
