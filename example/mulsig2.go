package example

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func MuSig2(alice, bob *btcec.PrivateKey,
	prevTxid *chainhash.Hash, prevPkScript []byte, prevTxout int, prevAmountSat, curAmountSat int64) *wire.MsgTx {
	newtx := wire.NewMsgTx(2)

	pubkeyList := []*btcec.PublicKey{alice.PubKey(), bob.PubKey()}

	aliceCtx, err := musig2.NewContext(alice, true,
		musig2.WithBip86TweakCtx(),
		musig2.WithEarlyNonceGen(),
		musig2.WithKnownSigners(pubkeyList),
	)
	if err != nil {
		panic(err)
	}

	aliceSession, err := aliceCtx.NewSession()
	if err != nil {
		panic(err)
	}

	bobCtx, err := musig2.NewContext(bob, true,
		musig2.WithBip86TweakCtx(), // bip86
		musig2.WithEarlyNonceGen(),
		musig2.WithKnownSigners(pubkeyList),
	)
	if err != nil {
		panic(err)
	}

	bobSession, err := bobCtx.NewSession()
	if err != nil {
		panic(err)
	}

	// txout to p2pr
	{
		// we use bip86, if not so, use `aliceCtx.TaprootInternalKey()` instead
		taprootKey, err := aliceCtx.CombinedKey()
		if err != nil {
			panic(err)
		}

		output, err := txscript.NewScriptBuilder().
			AddOp(txscript.OP_1).
			AddData(schnorr.SerializePubKey(taprootKey)).
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

		fetcher := txscript.NewCannedPrevOutputFetcher(prevPkScript, prevAmountSat)

		sigHash, err := txscript.CalcTaprootSignatureHash(
			txscript.NewTxSigHashes(newtx, fetcher),
			txscript.SigHashDefault, newtx, 0, fetcher,
		)
		if err != nil {
			panic(err)
		}

		aliceSig, err := aliceSession.Sign([32]byte(sigHash))
		if err != nil {
			panic(err)
		}

		bobSig, err := bobSession.Sign([32]byte(sigHash))
		if err != nil {
			panic(err)
		}

		if _, err := aliceSession.CombineSig(bobSig); err != nil {
			panic(err)
		}

		if _, err := bobSession.CombineSig(aliceSig); err != nil {
			panic(err)
		}

		if !aliceSession.FinalSig().IsEqual(bobSession.FinalSig()) {
			panic("inconsistent signature")
		}

		// default sign type
		txin.Witness = wire.TxWitness{aliceSession.FinalSig().Serialize()}
	}

	return newtx
}
