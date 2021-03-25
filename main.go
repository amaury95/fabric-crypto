package main

import (
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"signature.example.com/src/chaincode"
)

func main() {
	err := shim.Start(new(chaincode.SignatureChaincode))
	if err != nil {
		panic(err)
	}
}
