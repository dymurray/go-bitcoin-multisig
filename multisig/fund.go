package multisig

import (
	"github.com/soroushjp/go-bitcoin-multisig/base58check"
	"github.com/soroushjp/go-bitcoin-multisig/btcutils"

	"bytes"
	"encoding/hex"
	"fmt"
	"log"
)

func GenerateFund(flagPrivateKey string, flagInputTx string, flagAmount int, flagP2SHDestination string) {

	//Get private key as decoded raw bytes
	privateKey := base58check.Decode(flagPrivateKey)
	//In order to construct the raw transaction we need the input transaction hash,
	//the P2SH destination address, the number of satoshis to send, and the scriptSig
	//which is temporarily (prior to signing) the ScriptPubKey of the input transaction.
	publicKey, err := btcutils.NewPublicKey(privateKey)
	if err != nil {
		log.Fatal(err)
	}
	publicKeyHash, err := btcutils.Hash160(publicKey)
	if err != nil {
		log.Fatal(err)
	}
	tempScriptSig, err := btcutils.NewP2PKHScriptPubKey(publicKeyHash)
	if err != nil {
		log.Fatal(err)
	}
	redeemScriptHash := base58check.Decode(flagP2SHDestination)
	//Create our scriptPubKey
	scriptPubKey, err := btcutils.NewP2SHScriptPubKey(redeemScriptHash)
	if err != nil {
		log.Fatal(err)
	}
	//Create unsigned raw transaction
	rawTransaction, err := btcutils.NewRawTransaction(flagInputTx, flagAmount, tempScriptSig, scriptPubKey)
	if err != nil {
		log.Fatal(err)
	}
	//After completing the raw transaction, we append
	//SIGHASH_ALL in little-endian format to the end of the raw transaction.
	hashCodeType, err := hex.DecodeString("01000000")
	if err != nil {
		log.Fatal(err)
	}
	var rawTransactionBuffer bytes.Buffer
	rawTransactionBuffer.Write(rawTransaction)
	rawTransactionBuffer.Write(hashCodeType)
	rawTransactionWithHashCodeType := rawTransactionBuffer.Bytes()
	//Sign the raw transaction, and output it to the console.
	finalTransaction, err := signP2PKHTransaction(rawTransactionWithHashCodeType, privateKey, scriptPubKey, flagInputTx, flagAmount)
	if err != nil {
		log.Fatal(err)
	}
	finalTransactionHex := hex.EncodeToString(finalTransaction)
	//Output our final transaction
	fmt.Println("Your final transaction is")
	fmt.Println(finalTransactionHex)
}

func signP2PKHTransaction(rawTransaction []byte, privateKey []byte, scriptPubKey []byte, inputTx string, amount int) ([]byte, error) {
	publicKey, err := btcutils.NewPublicKey(privateKey)
	if err != nil {
		return nil, err
	}
	signature, err := btcutils.NewSignature(rawTransaction, privateKey)
	if err != nil {
		return nil, err
	}
	hashCodeType, err := hex.DecodeString("01")
	if err != nil {
		return nil, err
	}
	//signatureLength is +1 to add hashCodeType
	signatureLength := byte(len(signature) + 1)
	//Create scriptSig
	var buffer bytes.Buffer
	buffer.WriteByte(signatureLength)
	buffer.Write(signature)
	buffer.WriteByte(hashCodeType[0])
	buffer.WriteByte(byte(len(publicKey)))
	buffer.Write(publicKey)
	scriptSig := buffer.Bytes()
	//Finally create transaction with actual scriptSig
	signedRawTransaction, err := btcutils.NewRawTransaction(inputTx, amount, scriptSig, scriptPubKey)
	if err != nil {
		return nil, err
	}
	return signedRawTransaction, nil
}