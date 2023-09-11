package signer

import (
	"github.com/ginkgo981/pass-sdk-go/crypto/alg"
	"github.com/ginkgo981/pass-sdk-go/crypto/secp256k1"
	"github.com/ginkgo981/pass-sdk-go/crypto/secp256r1"
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
