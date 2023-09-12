package signer

import (
	"github.com/ginkgo981/pass-sdk-go/aggregator"
	"github.com/ginkgo981/pass-sdk-go/crypto/alg"
	"github.com/ginkgo981/pass-sdk-go/crypto/secp256k1"
	"github.com/ginkgo981/pass-sdk-go/crypto/secp256r1"
	"github.com/ginkgo981/pass-sdk-go/utils"
	"github.com/nervosnetwork/ckb-sdk-go/v2/address"
	"github.com/nervosnetwork/ckb-sdk-go/v2/types"
)

const (
	native byte = 1
	subkey byte = 2
)

type AlgPrivKey struct {
	PrivKey string
	Alg     alg.AlgIndex
}

func SignNativeUnlockTx(tx *types.Transaction, algKey AlgPrivKey, webAuthn *WebAuthnMsg) error {
	if algKey.Alg == alg.Secp256r1 {
		key := secp256r1.ImportKey(algKey.PrivKey)
		return signSecp256r1Tx(tx, key, native, webAuthn)
	}

	key := secp256k1.ImportKey(algKey.PrivKey)
	return signSecp256k1Tx(tx, key, native)
}

func BuildOutputTypeWithSubkeySmt(tx *types.Transaction, algKey AlgPrivKey, addr *address.Address, indexerUrl string) error {
	var pubkeyHash []byte

	if algKey.Alg == alg.Secp256r1 {
		key := secp256r1.ImportKey(algKey.PrivKey)
		pubkeyHash = key.PubkeyHash()
	} else {
		key := secp256k1.ImportKey(algKey.PrivKey)
		pubkeyHash = key.PubkeyHash()
	}

	rpc := aggregator.NewRPCClient(indexerUrl)
	unlockSmt, err := rpc.GetExtensionSubKeySmt(addr, pubkeyHash, algKey.Alg, 0)
	if err != nil {
		return err
	}

	witnesses := tx.Witnesses
	firstWitnessArgs, err := types.DeserializeWitnessArgs(witnesses[0])
	unlockBytes, err := utils.HexToBytes(unlockSmt.SmtRootHash)
	if err != nil {
		return err
	}

	firstWitnessArgs.OutputType = unlockBytes
	tx.Witnesses[0] = firstWitnessArgs.Serialize()

	return nil
}
