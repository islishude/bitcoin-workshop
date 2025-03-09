package example

import (
	"fmt"

	"github.com/btcsuite/btcd/rpcclient"
)

func JsonrpcClient() {
	btcrpc, err := rpcclient.New(&rpcclient.ConnConfig{
		// Note: Host = "host:port" or "host:port/path", port is required!
		Host:         "go.getblock.io:443/xxxx",
		Params:       "mainnet",
		HTTPPostMode: true,
		DisableTLS:   false,
		User:         "placeholder",
		Pass:         "placeholder", // required even if you don't use it
	}, nil)
	if err != nil {
		panic(err)
	}
	defer btcrpc.Shutdown()

	height, err := btcrpc.GetBlockCount()
	if err != nil {
		panic(err)
	}

	blockHash, err := btcrpc.GetBlockHash(height)
	if err != nil {
		panic(err)
	}

	block, err := btcrpc.GetBlock(blockHash)
	if err != nil {
		panic(err)
	}
	fmt.Println(block.BlockHash())
}
