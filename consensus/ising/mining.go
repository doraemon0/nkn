package ising

import (
	"math/rand"
	"time"

	. "github.com/nknorg/nkn/common"
	"github.com/nknorg/nkn/core/contract/program"
	"github.com/nknorg/nkn/core/ledger"
	"github.com/nknorg/nkn/core/signature"
	"github.com/nknorg/nkn/core/transaction"
	"github.com/nknorg/nkn/core/transaction/payload"
	"github.com/nknorg/nkn/crypto"
	"github.com/nknorg/nkn/crypto/util"
	"github.com/nknorg/nkn/por"
	"github.com/nknorg/nkn/vault"

	"github.com/golang/protobuf/proto"
	"github.com/nknorg/nkn/util/log"
)

type PayeeInfo struct {
	payee  Uint160
	amount Fixed64
}

type Mining interface {
	BuildBlock(height uint32, winningHash Uint256, winningHashType ledger.WinningHashType) (*ledger.Block, error)
}

type BuiltinMining struct {
	account      *vault.Account            // local account
	txnCollector *transaction.TxnCollector // transaction pool
}

func NewBuiltinMining(account *vault.Account, txnCollector *transaction.TxnCollector) *BuiltinMining {

	return &BuiltinMining{
		account:      account,
		txnCollector: txnCollector,
	}
}

func isPayeeExist(pi []*PayeeInfo, payee Uint160) (*PayeeInfo, bool) {
	var tmp *PayeeInfo
	for _, v := range pi {
		if v.payee.CompareTo(payee) == 0 {
			tmp = v
			return tmp, true
		}
	}

	return nil, false
}

func (bm *BuiltinMining) BuildBlock(height uint32, winningHash Uint256,
	winningHashType ledger.WinningHashType) (*ledger.Block, error) {
	var txnList []*transaction.Transaction
	var txnHashList []Uint256

	// create Coinbase transaction
	coinbase := bm.CreateCoinbaseTransaction()
	txnList = append(txnList, coinbase)
	txnHashList = append(txnHashList, coinbase.Hash())

	txns := bm.txnCollector.Collect()
	for txnHash, txn := range txns {
		if !ledger.DefaultLedger.Store.IsTxHashDuplicate(txnHash) {
			txnList = append(txnList, txn)
			txnHashList = append(txnHashList, txnHash)
		}
	}

	m := make(map[Uint160][]*PayeeInfo)
	n := make(map[Uint160]Fixed64)
	// create Pay transaction
	for _, t := range txns {
		if t.TxType == transaction.Commit {
			payload := t.Payload.(*payload.Commit)
			sigchain := &por.SigChain{}
			proto.Unmarshal(payload.SigChain, sigchain)
			if sigchain.Length() < 3 {
				log.Warn("signature chain is not long enough")
				continue
			}

			senderHash, err := PublicKeyToScriptHash(sigchain.GetSrcPubkey())
			if err != nil {
				return nil, err
			}
			senderPrepaidAmount, senderRates, err := ledger.DefaultLedger.Store.GetPrepaidInfo(*senderHash)
			if err != nil || senderPrepaidAmount == nil || *senderPrepaidAmount <= 0 {
				log.Warn("sender asset error")
				continue
			}
			if _, ok := n[*senderHash]; !ok {
				n[*senderHash] = *senderPrepaidAmount
			}

			relayerCount := sigchain.Length() - 2
			paymentAmount := *senderRates / Fixed64(relayerCount)
			for _, e := range sigchain.Elems[:relayerCount] {
				payeeHash, err := PublicKeyToScriptHash(e.NextPubkey)
				if err != nil {
					return nil, err
				}
				pInfo := &PayeeInfo{
					payee:  *payeeHash,
					amount: paymentAmount,
				}
				if n[*senderHash] < pInfo.amount {
					break
				} else {
					n[*senderHash] -= pInfo.amount
				}

				if _, ok := m[*senderHash]; ok {
					p, exist := isPayeeExist(m[*senderHash], pInfo.payee)
					if !exist {
						m[*senderHash] = append(m[*senderHash], pInfo)
					} else {
						p.amount += pInfo.amount
					}
				} else {
					m[*senderHash] = append(m[*senderHash], pInfo)
				}
			}
		}
	}
	payTxns := CreatePayTransaction(m)
	for _, payTxn := range payTxns {
		txnList = append(txnList, payTxn)
		txnHashList = append(txnHashList, payTxn.Hash())
	}

	txnRoot, err := crypto.ComputeRoot(txnHashList)
	if err != nil {
		return nil, err
	}
	encodedPubKey, err := bm.account.PublicKey.EncodePoint(true)
	if err != nil {
		return nil, err
	}
	header := &ledger.Header{
		Version:          0,
		PrevBlockHash:    ledger.DefaultLedger.Store.GetCurrentBlockHash(),
		Timestamp:        time.Now().Unix(),
		Height:           height,
		ConsensusData:    rand.Uint64(),
		TransactionsRoot: txnRoot,
		NextBookKeeper:   Uint160{},
		WinningHash:      winningHash,
		WinningHashType:  winningHashType,
		Signer:           encodedPubKey,
		Signature:        nil,
		Program: &program.Program{
			Code:      []byte{0x00},
			Parameter: []byte{0x00},
		},
	}
	hash := signature.GetHashForSigning(header)
	sig, err := crypto.Sign(bm.account.PrivateKey, hash)
	if err != nil {
		return nil, err
	}
	header.Signature = append(header.Signature, sig...)

	block := &ledger.Block{
		Header:       header,
		Transactions: txnList,
	}

	return block, nil
}

func (bm *BuiltinMining) CreateCoinbaseTransaction() *transaction.Transaction {
	return &transaction.Transaction{
		TxType:         transaction.Coinbase,
		PayloadVersion: 0,
		Payload:        &payload.Coinbase{},
		Attributes: []*transaction.TxnAttribute{
			{
				Usage: transaction.Nonce,
				Data:  util.RandomBytes(transaction.TransactionNonceLength),
			},
		},
		Inputs: []*transaction.TxnInput{},
		Outputs: []*transaction.TxnOutput{
			{
				AssetID:     ledger.DefaultLedger.Blockchain.AssetID,
				Value:       10 * StorageFactor,
				ProgramHash: bm.account.ProgramHash,
			},
		},
		Programs: []*program.Program{},
	}
}

func CreatePayTransaction(m map[Uint160][]*PayeeInfo) []*transaction.Transaction {
	var txns []*transaction.Transaction

	for sender, payeeInfos := range m {
		var outputs []*transaction.TxnOutput
		var totalAmount Fixed64
		for _, payeeInfo := range payeeInfos {
			output := &transaction.TxnOutput{
				AssetID:     ledger.DefaultLedger.Blockchain.AssetID,
				Value:       payeeInfo.amount,
				ProgramHash: payeeInfo.payee,
			}
			totalAmount += payeeInfo.amount
			outputs = append(outputs, output)
		}
		log.Info("total payment amount: ", totalAmount)
		txn := &transaction.Transaction{
			TxType:         transaction.Pay,
			PayloadVersion: 0,
			Payload: &payload.Pay{
				Payer:  sender,
				Amount: totalAmount,
			},
			Attributes: []*transaction.TxnAttribute{
				{
					Usage: transaction.Nonce,
					Data:  util.RandomBytes(transaction.TransactionNonceLength),
				},
			},
			Inputs:   []*transaction.TxnInput{},
			Outputs:  outputs,
			Programs: []*program.Program{},
		}
		txns = append(txns, txn)
	}

	return txns
}
