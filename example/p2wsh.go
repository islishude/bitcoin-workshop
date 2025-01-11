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

func CreateP2WSHMultiSigTx(netwk *chaincfg.Params, alice, bob, cario *btcec.PrivateKey,
	prevTxHash *chainhash.Hash, prevTxOut uint32, prevAmountSat, fee int64) *wire.MsgTx {
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

		txin := wire.NewTxIn(wire.NewOutPoint(prevTxHash, prevTxOut), nil, nil)
		txin.Sequence = wire.MaxTxInSequenceNum - 5 // let it be replaceable
		newtx.AddTxIn(txin)
	}

	// add txout
	{
		scriptHash := sha256.Sum256(redeemScript)
		address, err := btcutil.NewAddressWitnessScriptHash(scriptHash[:], netwk)
		if err != nil {
			panic(err)
		}
		fmt.Println("P2WSH Address:", address)

		output, err := txscript.PayToAddrScript(address)
		if err != nil {
			panic(err)
		}
		txout := wire.NewTxOut(prevAmountSat-fee, output)
		newtx.AddTxOut(txout)
	}

	// sign
	for txIdx, TxIn := range newtx.TxIn {
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

/*
Bip112 example

Lock script:

	OP_HASH160 OP_DUP <commitmentForTimeLock> OP_EQUAL
	OP_IF
		OP_DROP
		<timeLockNumber> OP_CHECKSEQUENCEVERIFY OP_DROP
		<alicePubkey> OP_CHECKSIG
	OP_ELSE
		<commitmentForMulsig> OP_EQUAL_VERIFY
		OP_2 <alicePubkey> <bobPubkey> OP_2 OP_CHECKMULTISIG
	OP_ENDIF

Unlock using timelock:

	<aliceSig> <timelock preimage>

Unlock using multi-sig:

	OP_0 <aliceSig> <bobSig> <mulsig preimage>
*/
func CreateBip112P2wsh(netwk *chaincfg.Params, aliceKey, bobKey *btcec.PrivateKey, prevTxHash *chainhash.Hash,
	prevTxout uint32, prevAmountSat, fee int64, timeLockNumber uint16, useTimelock bool,
	timelockPreimage, mulsigPreimage []byte) *wire.MsgTx {

	commitmentForTimeLock := btcutil.Hash160(timelockPreimage)
	commitmentForMulsig := btcutil.Hash160(mulsigPreimage)

	redeemScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_HASH160).
		AddOp(txscript.OP_DUP).
		AddData(commitmentForTimeLock).
		AddOp(txscript.OP_EQUAL).
		AddOp(txscript.OP_IF).
		AddOp(txscript.OP_DROP).
		AddInt64(int64(timeLockNumber)).
		AddOp(txscript.OP_CHECKSEQUENCEVERIFY).
		AddOp(txscript.OP_DROP).
		AddData(bobKey.PubKey().SerializeCompressed()).
		AddOp(txscript.OP_CHECKSIG).
		AddOp(txscript.OP_ELSE).
		AddData(commitmentForMulsig).
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
	address, err := btcutil.NewAddressWitnessScriptHash(witnessProg[:], netwk)
	if err != nil {
		panic(err)
	}
	fmt.Println("p2wsh address", address)

	prevPkScript, err := txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(witnessProg[:]).Script()
	if err != nil {
		panic(err)
	}
	fmt.Println("p2wsh pkScript", hex.EncodeToString(prevPkScript))

	newtx := wire.NewMsgTx(2) // tx version must be 2 to use bip-112

	// txout to the internal tss group address
	{
		output, err := txscript.PayToAddrScript(address)
		if err != nil {
			panic(err)
		}
		txout := wire.NewTxOut(prevAmountSat-fee, output)
		newtx.AddTxOut(txout)
	}

	if useTimelock {
		txin := wire.NewTxIn(wire.NewOutPoint(prevTxHash, uint32(prevTxout)), nil, nil)
		// the sequence number must be equal with the defined before
		txin.Sequence = uint32(timeLockNumber)
		newtx.AddTxIn(txin)
	} else {
		txin := wire.NewTxIn(wire.NewOutPoint(prevTxHash, uint32(prevTxout)), nil, nil)
		newtx.AddTxIn(txin)
	}

	// sign
	for txIdx, txin := range newtx.TxIn {
		sigHashes := txscript.NewTxSigHashes(newtx,
			txscript.NewCannedPrevOutputFetcher(prevPkScript, prevAmountSat))

		aliceSig, err := txscript.RawTxInWitnessSignature(
			newtx,
			sigHashes,
			txIdx,
			prevAmountSat,
			redeemScript,
			txscript.SigHashAll,
			aliceKey,
		)
		if err != nil {
			panic(err)
		}

		// txin using time lock
		if useTimelock {
			txin.Witness = wire.TxWitness{aliceSig, timelockPreimage, redeemScript}
		} else {
			bobSig, err := txscript.RawTxInWitnessSignature(
				newtx,
				sigHashes,
				txIdx,
				prevAmountSat,
				redeemScript, // the actual script to signed
				txscript.SigHashAll,
				bobKey,
			)
			if err != nil {
				panic(err)
			}
			txin.Witness = wire.TxWitness{[]byte{}, aliceSig, bobSig, mulsigPreimage, redeemScript}
		}
	}

	return newtx
}
