package signer

import (
	"encoding/base64"
	"encoding/binary"

	"github.com/ginkgo981/pass-sdk-go/utils"
	"github.com/nervosnetwork/ckb-sdk-go/v2/crypto/blake2b"
	"github.com/nervosnetwork/ckb-sdk-go/v2/types"
)

func GenerateWebAuthnChallenge(tx *types.Transaction) (string, error) {
	txHash := tx.ComputeHash()
	msg := txHash.Bytes()

	witnesses := tx.Witnesses

	firstWitnessArgs, err := types.DeserializeWitnessArgs(witnesses[0])
	if err != nil {
		return "", err
	}

	emptyWitness := types.WitnessArgs{
		Lock:       make([]byte, secp256k1EmptyWitnessLockLen),
		InputType:  firstWitnessArgs.InputType,
		OutputType: firstWitnessArgs.OutputType,
	}

	emptyWitnessBytes := emptyWitness.Serialize()
	bytesLen := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytesLen, uint64(len(msg)))
	msg = append(msg, bytesLen...)
	msg = append(msg, emptyWitnessBytes...)

	for i := 1; i < len(witnesses); i++ {
		bytes := append(msg, witnesses[i]...)
		bytesLen = make([]byte, 8)
		binary.LittleEndian.PutUint64(bytesLen, uint64(len(witnesses[i])))
		msg = append(msg, bytesLen...)
		msg = append(msg, bytes...)
	}
	msgHash := blake2b.Blake256(msg)
	msgHashHex := utils.BytesToHex(msgHash)

	challenge := make([]byte, 86)
	base64.StdEncoding.Encode(challenge, []byte(msgHashHex))

	return utils.BytesTo0xHex(challenge), nil
}
