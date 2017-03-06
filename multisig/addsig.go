// spend.go - Spending P2SH multisig funds to a Bitcoin address.
package multisig

import (
	"encoding/hex"
	"fmt"
	"log"
	"github.com/mgrottenthaler/mlcd/wire"
	"bytes"
	"github.com/prettymuchbryce/hellobitcoin/base58check"
)

//OutputAddsig formats and prints relevant outputs to the user.
func OutputAddsig(flagPrivateKeys string, flagRawTrans string) {
	finalTransactionHex := generateAddsig(flagPrivateKeys, flagRawTrans)
	//Output final transaction
	//Output our final transaction
	fmt.Printf(`
-----------------------------------------------------------------------------------------------------------------------------------
Your raw spending transaction is:
%v
Broadcast this transaction to spend your multisig P2SH funds.
-----------------------------------------------------------------------------------------------------------------------------------
`,
		finalTransactionHex,
	)
}

func generateAddsig(flagPrivateKeys string, flagRawTrans string) string {
	rawTransBytes, err := hex.DecodeString(flagRawTrans)
	if err != nil {
		log.Fatal(err)
	}

	//trans := DeserializeTrans(rawTransBytes)

	var trans_old wire.MsgTx
	trans_old.Deserialize(bytes.NewReader(rawTransBytes))

	var sigscript_old MultiSigScript
	sigscript_old.Deserialize(trans_old.TxIn[0].SignatureScript)

	vout_old := trans_old.TxIn[0].PreviousOutPoint.Index
	dest_old := getDestination(trans_old.TxOut[0].PkScript)
	redeem_old := hex.EncodeToString(sigscript_old.RedeemScript[2:])
	amount_old := trans_old.TxOut[0].Value
	inputtx_old := rawTransBytes[5:5+32]
	inputtx_old_reversed := make([]byte, len(inputtx_old))
	for i, _ := range inputtx_old  {
		inputtx_old_reversed[i] = inputtx_old[len(inputtx_old)-i-1]
	}
	inputtx_old_reversed_str := hex.EncodeToString(inputtx_old_reversed)

	newTrans, err := hex.DecodeString(GenerateSpend(flagPrivateKeys, vout_old, dest_old, redeem_old, inputtx_old_reversed_str, int(amount_old)))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hex.EncodeToString(newTrans))

	var trans_new wire.MsgTx
	trans_new.Deserialize(bytes.NewReader(newTrans))

	var sigscript_new MultiSigScript
	sigscript_new.Deserialize(trans_new.TxIn[0].SignatureScript)

	newScriptSig := createNewScriptSig(sigscript_old.Signature, sigscript_new.Signature, sigscript_new.RedeemScript)

	trans_new.TxIn[0].SignatureScript = trans_new.TxIn[0].SignatureScript[:0]
	trans_new.TxIn[0].SignatureScript = append(trans_new.TxIn[0].SignatureScript, newScriptSig...)

	var buf bytes.Buffer
	trans_new.Serialize(&buf)

	return hex.EncodeToString(buf.Bytes())
}

func getDestination(pkscript []byte) string {
	len_addr := byte(0x14)
	var addr []byte
	for i, e := range pkscript  {
		if e == len_addr {
			addr = pkscript[i+1:i+int(len_addr)+1]
		}
	}

	return base58check.Encode("6f", addr)
}

func createNewScriptSig(sig1 []byte, sig2 []byte, redeemScript []byte) []byte {
	var scriptsig []byte

	scriptsig = append(scriptsig[:], 0x00)
	scriptsig = append(scriptsig[:], sig1...)
	scriptsig = append(scriptsig[:], sig2...)
	scriptsig = append(scriptsig[:], redeemScript...)

	return scriptsig
}

type MultiSigScript struct {
	Signature []byte
	RedeemScript []byte
}

func (sig *MultiSigScript) Deserialize(sigscript []byte) {
	byte_marker := 0

	if sigscript[byte_marker] == 0x00 {
		byte_marker++
	}

	if sigscript[byte_marker] < 0x4c {
		sig.Signature = append(sig.Signature[:], sigscript[byte_marker:byte_marker+int(sigscript[byte_marker])+1]...)
		byte_marker += int(sigscript[byte_marker]) + 1
	}

	if sigscript[byte_marker] == 0x4c {
		sig.RedeemScript = append(sig.RedeemScript[:], sigscript[byte_marker:byte_marker+int(sigscript[byte_marker+1])+2]...)
		byte_marker += int(sigscript[byte_marker+1]) + 2
	}
}

func (sig *MultiSigScript) ToString() string {
	ret_str := ""
	ret_str += "Signature: " + hex.EncodeToString(sig.Signature) + "\n"
	ret_str += "Redeem-Script: " + hex.EncodeToString(sig.RedeemScript)

	return ret_str
}

/*
func DeserializeTrans(trans []byte) wire.MsgTx {
	var return_trans wire.MsgTx
	byte_marker := 0

	return_trans.Version = int32(binary.LittleEndian.Uint32(trans[byte_marker:byte_marker+4]))
	byte_marker += 4

	in_count, in_count_len := getVarInt(trans[byte_marker:])
	byte_marker += in_count_len

	var trans_ins = make([]wire.TxIn, in_count)

	for i := 0; i < in_count; i++ {
		trans_ins[i].PreviousOutPoint.Hash = chainhash.HashH(trans[byte_marker:byte_marker+32])
		byte_marker += 32
		trans_ins[i].PreviousOutPoint.Index = binary.LittleEndian.Uint32(trans[byte_marker:byte_marker+4])
		byte_marker += 4
		script_len, script_len_bytes := getVarInt(trans[byte_marker:])
		byte_marker += script_len_bytes
		trans_ins[i].SignatureScript = trans[byte_marker:byte_marker+script_len]
		byte_marker += script_len
		trans_ins[i].Sequence = binary.LittleEndian.Uint32(trans[byte_marker:byte_marker+4])
		byte_marker += 4

		return_trans.AddTxIn(&trans_ins[i])
	}

	out_count, out_count_len := getVarInt(trans[byte_marker:])
	byte_marker += out_count_len

	var trans_outs = make([]wire.TxOut, out_count)

	for i := 0; i < out_count; i++ {
		trans_outs[i].Value = int64(binary.LittleEndian.Uint64(trans[byte_marker:byte_marker+8]))
		byte_marker += 8
		script_len, script_len_bytes := getVarInt(trans[byte_marker:])
		byte_marker += script_len_bytes
		trans_outs[i].PkScript = trans[byte_marker:byte_marker+script_len]
		byte_marker += script_len

		return_trans.AddTxOut(&trans_outs[i])
	}

	return_trans.LockTime = binary.LittleEndian.Uint32(trans[byte_marker:byte_marker+4])
	byte_marker += 4

	return return_trans
}

func getVarInt(buf []byte) (int, int) {
	var len int
	var num_of_bytes int

	if buf[0] < 0xFD {
		len = int(buf[0])
		num_of_bytes = 1
	} else if buf[0] == 0xFD {
		len = int(binary.LittleEndian.Uint16(buf[0+1:0+3]))
		num_of_bytes = 3
	} else if buf[0] == 0xFE {
		len = int(binary.LittleEndian.Uint32(buf[0+1:0+5]))
		num_of_bytes = 5
	} else if buf[0] == 0xFF {
		len = int(binary.LittleEndian.Uint64(buf[0+1:0+9]))
		num_of_bytes = 9
	}

	return len, num_of_bytes
}
*/