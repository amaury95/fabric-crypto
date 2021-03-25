package chaincode_test

import (
	"crypto/ecdsa"
	// encoder "encoding/json"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	encoder "google.golang.org/protobuf/proto"
	"signature.example.com/src/chaincode"
	"signature.example.com/src/schema"

	"github.com/s7techlab/cckit/examples/cpaper_extended/testdata"
	idtestdata "github.com/s7techlab/cckit/identity/testdata"
	testcc "github.com/s7techlab/cckit/testing"
	expectcc "github.com/s7techlab/cckit/testing/expect"
)

type Wallet struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
	TxId       []byte
}

func FromSeed(seed string) (*Wallet, error) {
	privateKey, err := crypto.HexToECDSA(seed)
	if err != nil {
		return nil, err
	}
	publicKey := privateKey.Public()

	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("unable to cast public key to ecdsa.")
	}

	return &Wallet{
		PrivateKey: privateKey,
		PublicKey:  publicKeyECDSA,
	}, nil
}

func (w *Wallet) PublicKeyBytes() []byte {
	return crypto.FromECDSAPub(w.PublicKey)
}

func (w *Wallet) CreateTx(receiver *ecdsa.PublicKey, amount uint64) (*schema.Transaction, error) {
	receiverAddr := crypto.FromECDSAPub(receiver)

	tx := &schema.Transaction{
		Sender:    w.PublicKeyBytes(),
		Receiver:  receiverAddr,
		Amount:    amount,
		Signature: w.TxId,
	}

	rawtx, err := encoder.Marshal(tx)
	if err != nil {
		return nil, err
	}

	hash := crypto.Keccak256Hash(rawtx)

	signature, err := crypto.Sign(hash.Bytes(), w.PrivateKey)
	if err != nil {
		return nil, err
	}

	tx.Signature = signature

	return tx, nil
}

const (
	AddressSeed1 = "fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19"
	AddressSeed2 = "2345234523445a0b7ed4c543abad0f234534563ad6b3fe8d58345634568b6a13"
)

func TestTransactionChaincode(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Commercial Paper Suite")
}

var _ = Describe("Signature", func() {
	signatureChaincode := testcc.NewMockStub(`signature_chaincode`, new(chaincode.SignatureChaincode))

	BeforeSuite(func() {
		adminIdentity := testdata.Certificates[0].MustIdentity(idtestdata.DefaultMSP)
		expectcc.ResponseOk(signatureChaincode.From(adminIdentity).Init())
	})

	Describe("Signature Lifecycle", func() {

		It("registers an address", func() {
			wallet, err := FromSeed(AddressSeed1)
			Expect(err).To(BeNil())

			input := &schema.RequestRegister{
				Address: wallet.PublicKeyBytes(),
			}

			data, err := encoder.Marshal(input)
			Expect(err).To(BeNil())

			expectcc.ResponseOk(signatureChaincode.Invoke(`register`, data))
		})

		It("gets address balance", func() {
			wallet, err := FromSeed(AddressSeed1)
			Expect(err).To(BeNil())

			input := &schema.RequestBalance{
				Address: wallet.PublicKeyBytes(),
			}

			data, err := encoder.Marshal(input)
			Expect(err).To(BeNil())

			queryResponse := signatureChaincode.Query(`balance`, data)

			var response schema.ResponseBalance
			err = encoder.Unmarshal(queryResponse.Payload, &response)
			Expect(err).To(BeNil())

			// initial amount
			var expBalance uint64 = 100
			Expect(response.Balance.Amount).To(Equal(expBalance))
			Expect(response.Balance.Txid).NotTo(BeNil())
		})

		It("registers another address", func() {
			wallet, err := FromSeed(AddressSeed2)
			Expect(err).To(BeNil())

			input := &schema.RequestRegister{
				Address: wallet.PublicKeyBytes(),
			}

			data, err := encoder.Marshal(input)
			Expect(err).To(BeNil())

			expectcc.ResponseOk(signatureChaincode.Invoke(`register`, data))
		})

		It("sends a transaction from one address to another", func() {
			// create wallet 1
			wallet1, err := FromSeed(AddressSeed1)
			Expect(err).To(BeNil())

			// get wallet 1 txid to sign the transaction
			input := &schema.RequestBalance{
				Address: wallet1.PublicKeyBytes(),
			}

			data, err := encoder.Marshal(input)
			Expect(err).To(BeNil())

			queryResponse := signatureChaincode.Query(`balance`, data)
			var response schema.ResponseBalance
			err = encoder.Unmarshal(queryResponse.Payload, &response)
			Expect(err).To(BeNil())

			wallet1.TxId = response.Balance.Txid

			// create wallet 2
			wallet2, err := FromSeed(AddressSeed2)
			Expect(err).To(BeNil())

			// create and send transaction
			var sendAmount uint64 = 50
			tx, err := wallet1.CreateTx(wallet2.PublicKey, sendAmount)
			Expect(err).To(BeNil())

			input2 := &schema.RequestSend{Tx: tx}

			data2, err := encoder.Marshal(input2)
			Expect(err).To(BeNil())

			expectcc.ResponseOk(signatureChaincode.Invoke(`send`, data2))
		})

		It("returns the amount of first wallet updated", func() {
			wallet, err := FromSeed(AddressSeed1)
			Expect(err).To(BeNil())

			input := &schema.RequestBalance{
				Address: wallet.PublicKeyBytes(),
			}

			data, err := encoder.Marshal(input)
			Expect(err).To(BeNil())

			queryResponse := signatureChaincode.Query(`balance`, data)

			var response schema.ResponseBalance
			err = encoder.Unmarshal(queryResponse.Payload, &response)
			Expect(err).To(BeNil())

			var expBalance uint64 = 50
			Expect(response.Balance.Amount).To(Equal(expBalance))
			Expect(response.Balance.Txid).NotTo(BeNil())
		})

		It("returns the amount of second wallet updated", func() {
			wallet, err := FromSeed(AddressSeed2)
			Expect(err).To(BeNil())

			input := &schema.RequestBalance{
				Address: wallet.PublicKeyBytes(),
			}

			data, err := encoder.Marshal(input)
			Expect(err).To(BeNil())

			queryResponse := signatureChaincode.Query(`balance`, data)

			var response schema.ResponseBalance
			err = encoder.Unmarshal(queryResponse.Payload, &response)
			Expect(err).To(BeNil())

			var expBalance uint64 = 150
			Expect(response.Balance.Amount).To(Equal(expBalance))
			Expect(response.Balance.Txid).NotTo(BeNil())
		})
	})
})
