package pool

import (
	"fmt"
	"sync"

	"errors"
	"github.com/nknorg/nkn/common"
	"github.com/nknorg/nkn/core/ledger"
	. "github.com/nknorg/nkn/core/transaction"
	"github.com/nknorg/nkn/core/transaction/payload"
	. "github.com/nknorg/nkn/errors"
	"github.com/nknorg/nkn/por"
	"github.com/nknorg/nkn/util/log"
)

const (
	ExclusivedSigchainHeight = 3
)

type TxnPool struct {
	sync.RWMutex
	txnCnt        uint64                            // transaction count
	txnList       map[common.Uint256]*Transaction   // transaction which have been verified will put into this map
	issueSummary  map[common.Uint256]common.Fixed64 // transaction which pass the verify will summary the amout to this map
	inputUTXOList map[string]*Transaction           // transaction which pass the verify will add the UTXO to this map
	prepaidList   map[string]struct{}
}

func NewTxnPool() *TxnPool {
	return &TxnPool{
		txnCnt:        0,
		inputUTXOList: make(map[string]*Transaction),
		issueSummary:  make(map[common.Uint256]common.Fixed64),
		txnList:       make(map[common.Uint256]*Transaction),
		prepaidList:   make(map[string]struct{}),
	}
}

//append transaction to txnpool when check ok.
//1.check transaction. 2.check with ledger(db) 3.check with pool
func (tp *TxnPool) AppendTxnPool(txn *Transaction) ErrCode {
	//verify transaction with Concurrency
	if errCode := VerifyTransaction(txn); errCode != ErrNoError {
		log.Info("Transaction verification failed", txn.Hash())
		return errCode
	}
	if errCode := VerifyTransactionWithLedger(txn); errCode != ErrNoError {
		log.Info("Transaction verification with ledger failed", txn.Hash())
		return errCode
	}
	if errCode := tp.verifyTransactionWithTxnPool(txn); errCode != ErrNoError {
		log.Info("Transaction verification with transaction pool failed", txn.Hash())
		return errCode
	}

	//add the transaction to process scope
	tp.addtxnList(txn)

	// get signature chain from commit transaction then add it to POR server
	if txn.TxType == Commit {
		por.GetPorServer().AddSigChainFromTx(txn)
	}

	return ErrNoError
}

func (tp *TxnPool) GetTxnByCount(num int) map[common.Uint256]*Transaction {
	tp.RLock()
	defer tp.RUnlock()

	n := len(tp.txnList)
	if num < n {
		n = num
	}

	exclusivedHashes, err := por.GetPorServer().GetTxnHashBySigChainHeight(ledger.DefaultLedger.Store.GetHeight() +
		ExclusivedSigchainHeight)
	if err != nil {
		log.Error("collect transaction error: ", err)
		return nil
	}
	i := 0
	txns := make(map[common.Uint256]*Transaction, n)
	//TODO sort transaction list
	for hash, txn := range tp.txnList {
		if !isHashExist(hash, exclusivedHashes) {
			txns[hash] = txn
			i++
			if i >= n {
				break
			}
		}
	}

	return txns
}

//clean the trasaction Pool with committed block.
func (tp *TxnPool) CleanSubmittedTransactions(txns []*Transaction) error {
	tp.cleanTransactionList(txns)
	tp.cleanUTXOList(txns)
	tp.cleanIssueSummary(txns)
	tp.cleanPrepaidList(txns)
	return nil
}

//get the transaction by hash
func (tp *TxnPool) GetTransaction(hash common.Uint256) *Transaction {
	tp.RLock()
	defer tp.RUnlock()
	return tp.txnList[hash]
}

func (tp *TxnPool) GetAllTransactions() map[common.Uint256]*Transaction {
	tp.RLock()
	defer tp.RUnlock()

	txns := make(map[common.Uint256]*Transaction, len(tp.txnList))
	for hash, txn := range tp.txnList {
		txns[hash] = txn
	}

	return txns
}

//verify transaction with txnpool
func (tp *TxnPool) verifyTransactionWithTxnPool(txn *Transaction) ErrCode {
	// check if the transaction includes double spent UTXO inputs
	if err := tp.apendToUTXOPool(txn); err != nil {
		log.Info(err)
		return ErrDoubleSpend
	}
	if err := tp.checkPrepaidList(txn); err != nil {
		log.Info(err)
		return ErrDuplicatePrepaid
	}
	//check issue transaction weather occur exceed issue range.
	if ok := tp.summaryAssetIssueAmount(txn); !ok {
		log.Info(fmt.Sprintf("Check summary Asset Issue Amount failed with txn=%x", txn.Hash()))
		tp.removeTransaction(txn)
		return ErrSummaryAsset
	}

	return ErrNoError
}

//check and add to utxo list pool
func (this *TxnPool) apendToUTXOPool(txn *Transaction) error {
	reference, err := txn.GetReference()
	if err != nil {
		return err
	}
	inputs := []*TxnInput{}
	for k := range reference {
		if txn := this.getInputUTXOList(k); txn != nil {
			return NewErr(fmt.Sprintf("double spent UTXO inputs detected, "+
				"transaction hash: %x, input: %s, index: %s",
				txn.Hash(), k.ToString()[:64], k.ToString()[64:]))
		}
		inputs = append(inputs, k)
	}
	for _, v := range inputs {
		this.addInputUTXOList(txn, v)
	}

	return nil
}

//remove from associated map
func (tp *TxnPool) removeTransaction(txn *Transaction) {
	//1.remove from txnList
	tp.deltxnList(txn)
	//2.remove from UTXO list map
	result, err := txn.GetReference()
	if err != nil {
		log.Info(fmt.Sprintf("Transaction =%x not Exist in Pool when delete.", txn.Hash()))
		return
	}
	for input := range result {
		tp.delInputUTXOList(input)
	}
	//3.remove From Asset Issue Summary map
	if txn.TxType != IssueAsset {
		return
	}
	transactionResult := txn.GetMergedAssetIDValueFromOutputs()
	for k, delta := range transactionResult {
		tp.decrAssetIssueAmountSummary(k, delta)
	}
}

//clean txnpool utxo map
func (tp *TxnPool) cleanUTXOList(txs []*Transaction) {
	for _, txn := range txs {
		inputUtxos, _ := txn.GetReference()
		for Utxoinput, _ := range inputUtxos {
			tp.delInputUTXOList(Utxoinput)
		}
	}
}

//check and summary to issue amount Pool
func (tp *TxnPool) summaryAssetIssueAmount(txn *Transaction) bool {
	if txn.TxType != IssueAsset {
		return true
	}
	transactionResult := txn.GetMergedAssetIDValueFromOutputs()
	for k, delta := range transactionResult {
		//update the amount in txnPool
		tp.incrAssetIssueAmountSummary(k, delta)

		//Check weather occur exceed the amount when RegisterAsseted
		//1. Get the Asset amount when RegisterAsseted.
		txn, err := Store.GetTransaction(k)
		if err != nil {
			return false
		}
		if txn.TxType != RegisterAsset {
			return false
		}
		AssetReg := txn.Payload.(*payload.RegisterAsset)

		//2. Get the amount has been issued of tp assetID
		var quantity_issued common.Fixed64
		if AssetReg.Amount < common.Fixed64(0) {
			continue
		} else {
			quantity_issued, err = Store.GetQuantityIssued(k)
			if err != nil {
				return false
			}
		}

		//3. calc weather out off the amount when Registed.
		//AssetReg.Amount : amount when RegisterAsset of tp assedID
		//quantity_issued : amount has been issued of tp assedID
		//txnPool.issueSummary[k] : amount in transactionPool of tp assedID
		if AssetReg.Amount-quantity_issued < tp.getAssetIssueAmount(k) {
			return false
		}
	}
	return true
}

// clean the trasaction Pool with committed transactions.
func (tp *TxnPool) cleanTransactionList(txns []*Transaction) error {
	cleaned := 0
	txnsNum := len(txns)
	for _, txn := range txns {
		if txn.TxType == Coinbase {
			txnsNum = txnsNum - 1
			continue
		}
		if tp.deltxnList(txn) {
			cleaned++
		}
	}
	log.Debug(fmt.Sprintf("transaction pool cleaning, requested: %d, cleaned: %d, remains %d", txnsNum, cleaned, tp.GetTransactionCount()))
	return nil
}

func (tp *TxnPool) addtxnList(txn *Transaction) bool {
	tp.Lock()
	defer tp.Unlock()
	txnHash := txn.Hash()
	if _, ok := tp.txnList[txnHash]; ok {
		return false
	}
	tp.txnList[txnHash] = txn
	return true
}

func (tp *TxnPool) deltxnList(tx *Transaction) bool {
	tp.Lock()
	defer tp.Unlock()
	txHash := tx.Hash()
	if _, ok := tp.txnList[txHash]; !ok {
		return false
	}
	delete(tp.txnList, tx.Hash())
	return true
}

func (tp *TxnPool) copytxnList() map[common.Uint256]*Transaction {
	tp.RLock()
	defer tp.RUnlock()
	txnMap := make(map[common.Uint256]*Transaction, len(tp.txnList))
	for txnId, txn := range tp.txnList {
		txnMap[txnId] = txn
	}
	return txnMap
}

func (tp *TxnPool) GetTransactionCount() int {
	tp.RLock()
	defer tp.RUnlock()
	return len(tp.txnList)
}

func (tp *TxnPool) getInputUTXOList(input *TxnInput) *Transaction {
	tp.RLock()
	defer tp.RUnlock()
	return tp.inputUTXOList[input.ToString()]
}

func (tp *TxnPool) addInputUTXOList(tx *Transaction, input *TxnInput) bool {
	tp.Lock()
	defer tp.Unlock()
	id := input.ToString()
	_, ok := tp.inputUTXOList[id]
	if ok {
		return false
	}
	tp.inputUTXOList[id] = tx

	return true
}

func (tp *TxnPool) delInputUTXOList(input *TxnInput) bool {
	tp.Lock()
	defer tp.Unlock()
	id := input.ToString()
	_, ok := tp.inputUTXOList[id]
	if !ok {
		return false
	}
	delete(tp.inputUTXOList, id)
	return true
}

func (tp *TxnPool) incrAssetIssueAmountSummary(assetId common.Uint256, delta common.Fixed64) {
	tp.Lock()
	defer tp.Unlock()
	tp.issueSummary[assetId] = tp.issueSummary[assetId] + delta
}

func (tp *TxnPool) decrAssetIssueAmountSummary(assetId common.Uint256, delta common.Fixed64) {
	tp.Lock()
	defer tp.Unlock()
	amount, ok := tp.issueSummary[assetId]
	if !ok {
		return
	}
	amount = amount - delta
	if amount < common.Fixed64(0) {
		amount = common.Fixed64(0)
	}
	tp.issueSummary[assetId] = amount
}

func (tp *TxnPool) cleanIssueSummary(txs []*Transaction) {
	for _, v := range txs {
		if v.TxType == IssueAsset {
			transactionResult := v.GetMergedAssetIDValueFromOutputs()
			for k, delta := range transactionResult {
				tp.decrAssetIssueAmountSummary(k, delta)
			}
		}
	}
}

func (tp *TxnPool) getAssetIssueAmount(assetId common.Uint256) common.Fixed64 {
	tp.RLock()
	defer tp.RUnlock()
	return tp.issueSummary[assetId]
}

func isHashExist(hash common.Uint256, hashSet []common.Uint256) bool {
	for _, h := range hashSet {
		if h.CompareTo(hash) == 0 {
			return true
		}
	}

	return false
}

func (tp *TxnPool) checkPrepaidList(txn *Transaction) error {
	switch txn.TxType {
	case Prepaid:
		programHashes, err := txn.GetProgramHashes()
		if err != nil {
			return err
		}
		str := common.BytesToHexString(programHashes[0].ToArrayReverse())
		if _, ok := tp.prepaidList[str]; ok {
			return errors.New("duplicated prepaid transaction detected")
		}
		tp.prepaidList[str] = struct{}{}
	}

	return nil
}

func (tp *TxnPool) cleanPrepaidList(txns []*Transaction) error {
	for _, txn := range txns {
		switch txn.TxType {
		case Prepaid:
			programHashes, err := txn.GetProgramHashes()
			if err != nil {
				return err
			}
			str := common.BytesToHexString(programHashes[0].ToArrayReverse())
			delete(tp.prepaidList, str)
		}
	}
	return nil
}
