package signer

import (
	"encoding/base64"
	"encoding/binary"

	"github.com/ginkgo981/pass-sdk-go/crypto/secp256r1"
	"github.com/ginkgo981/pass-sdk-go/crypto/sha256"
	"github.com/ginkgo981/pass-sdk-go/utils"
	"github.com/nervosnetwork/ckb-sdk-go/v2/crypto/blake2b"
	"github.com/nervosnetwork/ckb-sdk-go/v2/types"
)

type WebAuthnMsg struct {
	AuthData   string
	ClientData string
}

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

func signSecp256r1Tx(tx *types.Transaction, key *secp256r1.Key, mode byte, webAuthn *WebAuthnMsg) error {
	clientDataBytes, err := utils.HexToBytes(webAuthn.ClientData)
	if err != nil {
		return err
	}

	clientDataHash := sha256.Sha256(clientDataBytes)
	authData, err := utils.HexToBytes(webAuthn.AuthData)
	if err != nil {
		return err
	}

	signData := authData
	signData = append(signData, clientDataHash...)
	signature := key.Sign(sha256.Sha256(signData))
	_, publicKey := key.Pubkey()

	firstWitnessArgs, err := types.DeserializeWitnessArgs(tx.Witnesses[0])
	if err != nil {
		return err
	}

	witnessArgsLock := []byte{mode}
	witnessArgsLock = append(witnessArgsLock, publicKey...)
	witnessArgsLock = append(witnessArgsLock, signature...)
	witnessArgsLock = append(witnessArgsLock, authData...)
	witnessArgsLock = append(witnessArgsLock, clientDataBytes...)
	firstWitnessArgs.Lock = witnessArgsLock

	tx.Witnesses[0] = firstWitnessArgs.Serialize()
	return nil
}
