package main

import (
	"github.com/soroushjp/go-bitcoin-multisig/base58check"
	"github.com/soroushjp/go-bitcoin-multisig/btcutils"

	"encoding/hex"
	"flag"
	"fmt"
	"log"
)

var flagKeyCount int

func main() {

	flag.IntVar(&flagKeyCount, "count", 1, "No. of key pairs to generate. Default is 1")
	flag.Parse()

	if flagKeyCount < 1 || flagKeyCount > 100 {
		log.Fatal("--count <count> must be between 1 and 100")
	}

	fmt.Println("----------------------------------------------------------------------")
	fmt.Println("THESE KEY PAIRS ARE PSEUDORANDOM. FOR DEMONSTRATION PURPOSES ONLY.")
	fmt.Println("----------------------------------------------------------------------")
	fmt.Println("Each generated keypair includes: ")
	fmt.Println("* Your private key\t\t\t-- Keep this private, needed to spend received Bitcoins.")
	fmt.Println("* Your public key\t\t\t-- in HEX format. This is required to generate multisig destination address.")
	fmt.Println("* Your public destination address\t-- Give this to other people to send you Bitcoins.")
	fmt.Println("----------------------------------------------------------------------")

	for i := 0; i <= flagKeyCount-1; i++ {

		//Generate private key
		privateKey := btcutils.NewPrivateKey()
		//Generate public key from private key
		publicKey, err := btcutils.NewPublicKey(privateKey)
		if err != nil {
			log.Fatal(err)
		}
		//Get hex encoded version of public key
		publicKeyHex := hex.EncodeToString(publicKey)
		//Get public address by hashing with SHA256 and RIPEMD160 and base58 encoding with mainnet prefix 00
		publicKeyHash, err := btcutils.Hash160(publicKey)
		if err != nil {
			log.Fatal(err)
		}
		publicAddress := base58check.Encode("00", publicKeyHash)
		//Get private key in Wallet Import Format (WIF) by base58 encoding with prefix 80
		privateKeyWIF := base58check.Encode("80", privateKey)

		//Output private key in WIF format, public key as hex and P2PKH public address
		fmt.Println("--------------")
		fmt.Printf("KEY #%d\n\n", i+1)
		fmt.Println("Private key: ")
		fmt.Println(privateKeyWIF, "\n")
		fmt.Println("Public key in HEX: ")
		fmt.Println(publicKeyHex, "\n")
		fmt.Println("Public Bitcoin address: ")
		fmt.Println(publicAddress)
		fmt.Println("--------------")
	}

}