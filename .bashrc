WALLET_NAME=test

bitcoin-cli loadwallet $WALLET_NAME > /dev/null 2>&1
if [ $? -eq 18 ]; then
    bitcoin-cli createwallet $WALLET_NAME > /dev/null 2>&1
    bitcoin-cli getnewaddress $WALLET_NAME > /dev/null 2>&1
fi

export COINBASE=$(bitcoin-cli getaddressesbylabel $WALLET_NAME | grep -oP '"\K[^"]+(?=":)' | head -n 1)

txget() {
    local verbosity=${2:-2}
    bitcoin-cli getrawtransaction "$1" $verbosity
}

txsend() {
    bitcoin-cli sendrawtransaction "$1"
}

txtest() {
    bitcoin-cli testmempoolaccept '["'$1'"]'
}

mine() {
    local blocks=${1:-1}
    bitcoin-cli generatetoaddress "$blocks" $COINBASE
}

fund() {
    local address=${1:?Address cannot be empty}
    local amount=${2:-1}
    bitcoin-cli sendtoaddress $address $amount
}

alias b='bitcoin-cli'
