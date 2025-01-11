package example

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"math"
	"slices"
	"sync"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

var sha256Pool = &sync.Pool{
	New: func() any {
		return sha256.New()
	},
}

func DoubleSHA256Sum(data []byte) []byte {
	h := sha256Pool.Get().(hash.Hash)
	defer sha256Pool.Put(h)

	h.Reset()
	_, _ = h.Write(data)

	buf := make([]byte, 0, 32)
	first := h.Sum(buf)

	h.Reset()
	_, _ = h.Write(first)
	return h.Sum(buf)
}

func ComputeParentNode(left, right *chainhash.Hash) *chainhash.Hash {
	combined := slices.Concat(left[:], right[:])

	parent := new(chainhash.Hash)
	copy(parent[:], DoubleSHA256Sum(combined))
	return parent
}

func cloneChainHash(h *chainhash.Hash) *chainhash.Hash {
	res := new(chainhash.Hash)
	copy(res[:], h[:])
	return res
}

func ComputeMerkleRoot(txhs []*chainhash.Hash) *chainhash.Hash {
	if len(txhs) == 0 {
		return nil
	}

	if len(txhs) == 1 {
		return cloneChainHash(txhs[0])
	}

	if len(txhs)&1 != 0 {
		padding := new(chainhash.Hash)
		_ = padding.SetBytes(txhs[len(txhs)-1][:])
		txhs = append(txhs, padding)
	}

	parents := make([]*chainhash.Hash, 0, len(txhs)/2)
	for i := 0; i < len(txhs); i += 2 {
		parents = append(parents, ComputeParentNode(txhs[i], txhs[i+1]))
	}

	return ComputeMerkleRoot(parents)
}

func ComputeMerkleRootAndProof(txhs []*chainhash.Hash, txIndex int, proof *[]*chainhash.Hash) *chainhash.Hash {
	if len(txhs) == 0 {
		return nil
	}

	if len(txhs) == 1 {
		return cloneChainHash(txhs[0])
	}

	if len(txhs)&1 != 0 {
		txhs = append(txhs, cloneChainHash(txhs[len(txhs)-1]))
	}

	var newIndex int
	parents := make([]*chainhash.Hash, 0, len(txhs)/2)
	for i := 0; i < len(txhs); i += 2 {
		parents = append(parents, ComputeParentNode(txhs[i], txhs[i+1]))

		if i == txIndex || i+1 == txIndex {
			if i == txIndex {
				*proof = append(*proof, cloneChainHash(txhs[i+1]))
			} else {
				*proof = append(*proof, cloneChainHash(txhs[i]))
			}
			newIndex = len(parents) - 1
		}
	}

	return ComputeMerkleRootAndProof(parents, newIndex, proof)
}

func VerifyProof(txid, root *chainhash.Hash, txIndex int, path []*chainhash.Hash) bool {
	if txid != nil && txid.IsEqual(root) && txIndex == 0 && len(path) == 0 {
		return true
	}

	current := cloneChainHash(txid)
	for i := 0; i < len(path); i++ {
		if txIndex&1 == 0 {
			current = ComputeParentNode(current, path[i])
		} else {
			current = ComputeParentNode(path[i], current)
		}
		txIndex >>= 1
	}

	return current.IsEqual(root)
}

// proof = txid || intermediateNodes || merkleRoot
func VerifyRawProof(proof []byte, index int) bool {
	if len(proof)%32 != 0 {
		return false
	}

	if len(proof) == 64 {
		return bytes.Equal(proof[:32], proof[32:])
	}

	buf := make([]byte, 64)
	current := proof[:32]
	for i := 1; i < (len(proof)/32)-1; i++ {
		start := i * 32
		end := start + 32
		next := proof[start:end]
		if index&1 == 0 {
			copy(buf[:32], current)
			copy(buf[32:], next)
			current = DoubleSHA256Sum(buf)
		} else {
			copy(buf[:32], next)
			copy(buf[32:], current)
			current = DoubleSHA256Sum(buf)
		}
		index >>= 1
	}

	return bytes.Equal(current, proof[len(proof)-32:])
}

func VerifyRawProof2(txid, root, intermediate []byte, index int) bool {
	if len(txid) != 32 || len(root) != 32 || len(intermediate)%32 != 0 {
		return false
	}

	if len(intermediate) == 0 {
		return bytes.Equal(txid, root)
	}

	current := txid
	for i := 0; i < len(intermediate)/32; i++ {
		start := i * 32
		end := start + 32
		next := intermediate[start:end]
		if index&1 == 0 {
			current = DoubleSHA256Sum(slices.Concat(current, next))
		} else {
			current = DoubleSHA256Sum(slices.Concat(next, current))
		}
		index >>= 1
	}

	return index == 0 && bytes.Equal(current, root)
}

func MerkelProof(txid []string, root string) {
	// Note: the txid from btc rpc is big-endian, but it uses little-endian internally
	var txHashs = make([]*chainhash.Hash, 0, len(txid))
	for _, txHash := range txid {
		hash, err := chainhash.NewHashFromStr(txHash)
		if err != nil {
			panic(err)
		}
		txHashs = append(txHashs, hash)
	}

	merkleRoot, err := chainhash.NewHashFromStr(root)
	if err != nil {
		panic(err)
	}

	for txIndex := 0; txIndex < len(txHashs); txIndex++ {
		proof := make([]*chainhash.Hash, 0, int64(math.Log2(float64(len(txid))))+1)
		fmt.Println("proof for", txIndex)
		fmt.Println(merkleRoot.IsEqual((ComputeMerkleRootAndProof(txHashs, txIndex, &proof))))
		fmt.Println(VerifyProof(txHashs[txIndex], merkleRoot, txIndex, proof))

		raw := bytes.NewBuffer(make([]byte, 0, 32*len(proof)+2))
		// raw.Write(txHashs[txIndex][:])
		for _, p := range proof {
			raw.Write(p[:])
		}
		// raw.Write(merkleRoot[:])
		// fmt.Println(example.VerifyRawProof(raw.Bytes(), txIndex))
		fmt.Println(hex.EncodeToString(raw.Bytes()))
	}
}
