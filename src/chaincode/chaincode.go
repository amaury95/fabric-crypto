package chaincode

import (
	"bytes"
	// encoder "encoding/json"
	"errors"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/protos/peer"
	encoder "google.golang.org/protobuf/proto"
	"signature.example.com/src/schema"
)

type SignatureChaincode struct{}

func (s *SignatureChaincode) Init(stub shim.ChaincodeStubInterface) peer.Response {
	return shim.Success(nil)
}

func (s *SignatureChaincode) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	function, args := stub.GetFunctionAndParameters()

	switch function {
	case "register":
		// REGISTER
		if err := checkArgsLen(args, 1); err != nil {
			return s.Errorf(err.Error())
		}

		var input schema.RequestRegister
		if err := encoder.Unmarshal([]byte(args[0]), &input); err != nil {
			return s.Errorf(err.Error())
		}

		response, err := s.register(stub, &input)
		if err != nil {
			return s.Errorf(err.Error())
		}

		data, _ := encoder.Marshal(response)
		return shim.Success(data)

	case "balance":
		// BALANCE
		if err := checkArgsLen(args, 1); err != nil {
			return s.Errorf(err.Error())
		}

		var input schema.RequestBalance
		if err := encoder.Unmarshal([]byte(args[0]), &input); err != nil {
			return s.Errorf(err.Error())
		}

		response, err := s.balance(stub, &input)
		if err != nil {
			return s.Errorf(err.Error())
		}

		data, _ := encoder.Marshal(response)
		return shim.Success(data)

	case "send":
		// SEND
		if err := checkArgsLen(args, 1); err != nil {
			return s.Errorf(err.Error())
		}

		var input schema.RequestSend
		if err := encoder.Unmarshal([]byte(args[0]), &input); err != nil {
			return s.Errorf(err.Error())
		}

		response, err := s.send(stub, &input)
		if err != nil {
			return s.Errorf(err.Error())
		}

		data, _ := encoder.Marshal(response)
		return shim.Success(data)

	default:
		return s.Errorf("incorrect function name: %s", function)
	}
}

func (s *SignatureChaincode) register(stub shim.ChaincodeStubInterface, input *schema.RequestRegister) (*schema.ResponseRegister, error) {
	// check account doesn't exist
	state, err := stub.GetState(s.Key(input.Address))
	if err != nil {
		return nil, err
	} else if state != nil {
		return nil, errors.New("account already registered")
	}

	// generate genesis txid
	txid := crypto.Keccak256Hash(input.Address)

	// setup status
	balance := schema.Balance{
		Txid:   txid.Bytes(),
		Amount: 100,
	}

	// put state into blockchain
	state, _ = encoder.Marshal(&balance)
	if err := stub.PutState(s.Key(input.Address), state); err != nil {
		return nil, err
	}

	// return state
	return &schema.ResponseRegister{Balance: &balance}, nil
}

func (s *SignatureChaincode) balance(stub shim.ChaincodeStubInterface, input *schema.RequestBalance) (*schema.ResponseBalance, error) {
	// get state from address
	state, err := stub.GetState(s.Key(input.Address))
	if err != nil {
		return nil, err
	}

	var balance schema.Balance
	if err := encoder.Unmarshal(state, &balance); err != nil {
		return nil, err
	}

	return &schema.ResponseBalance{Balance: &balance}, nil
}

func (s *SignatureChaincode) send(stub shim.ChaincodeStubInterface, input *schema.RequestSend) (*schema.ResponseSend, error) {
	// retrieve sender and receiver balances
	sender, err := s.balance(stub, &schema.RequestBalance{Address: input.Tx.Sender})
	if err != nil {
		return nil, err
	}
	receiver, err := s.balance(stub, &schema.RequestBalance{Address: input.Tx.Receiver})
	if err != nil {
		return nil, err
	}

	// check transaction signature
	txid, err := s.verifySignature(input.Tx, sender.Balance.Txid)
	if err != nil {
		return nil, err
	}

	// update sender and receiver balances
	sender.Balance.Amount -= input.Tx.Amount
	sender.Balance.Txid = txid

	receiver.Balance.Amount += input.Tx.Amount

	// updating states into the ledger
	senderState, _ := encoder.Marshal(sender.Balance)
	if err := stub.PutState(s.Key(input.Tx.Sender), senderState); err != nil {
		return nil, err
	}

	receiverState, _ := encoder.Marshal(receiver.Balance)
	if err := stub.PutState(s.Key(input.Tx.Receiver), receiverState); err != nil {
		return nil, err
	}

	// return sender's state
	return &schema.ResponseSend{Balance: sender.Balance}, nil
}

func (s *SignatureChaincode) Key(address []byte) string {
	return hexutil.Encode(address)
}

func (s *SignatureChaincode) verifySignature(tx *schema.Transaction, txid []byte) ([]byte, error) {
	// get the signature and the hash to be checked.
	signature := tx.Signature
	tx.Signature = txid

	rawtx, _ := encoder.Marshal(tx)
	hash := crypto.Keccak256Hash(rawtx)

	// check the signature was provided from the given public key
	sigPubKey, err := crypto.Ecrecover(hash.Bytes(), signature)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(tx.Sender, sigPubKey) {
		return nil, errors.New("invalid sender for signature")
	}

	// check the signature matches the transaction hash
	if !crypto.VerifySignature(sigPubKey, hash.Bytes(), signature[:64]) {
		return nil, errors.New("invalid signature")
	}

	return hash.Bytes(), nil
}
