package chaincode

import (
	"fmt"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/protos/peer"
)

func (s *SignatureChaincode) Errorf(format string, args ...interface{}) peer.Response {
	format = "SignatureChaincode error: " + format
	return shim.Error(fmt.Sprintf(format, args...))
}

func (s *SignatureChaincode) Logf(format string, args ...interface{}) peer.Response {
	format = "SignatureChaincode: " + format
	return shim.Error(fmt.Sprintf(format, args...))
}

func checkArgsLen(args []string, length int) (err error) {
	if len(args) < length {
		err = fmt.Errorf("arguments length expected: %d received: %d", length, len(args))
	}
	return
}
