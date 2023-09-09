package secp256k1

import (
	"fmt"

	"github.com/ginkgo981/pass-sdk-go/crypto/sha256"
	"github.com/ginkgo981/pass-sdk-go/utils"
)

func ExampleImportKey() {
	key := ImportKey("0x4271c23380932c74a041b4f56779e5ef60e808a127825875f906260f1f657761")
	hexKey := utils.BytesTo0xHex(key.Bytes())
	fmt.Println(hexKey)

	// Output:
	// 0x4271c23380932c74a041b4f56779e5ef60e808a127825875f906260f1f657761
}

func ExamplePubKey() {
	_, pk := ImportKey("0x4271c23380932c74a041b4f56779e5ef60e808a127825875f906260f1f657761").Pubkey()
	hexPubKey := utils.BytesTo0xHex(pk)
	fmt.Println(hexPubKey)

	// Output:
	// 0x1270b9173d60f8f3ea3cd9e96f9f0ee28c6cf02d51bab0c29851c54d4f734f66029830d23d4260392187c2cd473e867d8c28c6d6f3a1252ebe5bbd3b9881cfde
}

func ExampleSignMessage() {
	key := ImportKey("0x4271c23380932c74a041b4f56779e5ef60e808a127825875f906260f1f657761")
	message := []byte("hello world")
	signature := key.Sign(sha256.Sha256(message))
	hexSignature := utils.BytesTo0xHex(signature)
	fmt.Println(hexSignature)

	// Output:
	// 0x9d502b90a9104ca53e3e3a6563447f95a77455a1b7e468621651dcf64691c2e4a73cf4480fc680a6f7443cb8b15920df08a8e4065c1a5c80e7de8f83ead1951f
}

func ExampleRecoverPubKey() {
	key := ImportKey("0x2262cd6c965d0065f93fb1fce03444e7f2a354b215b16dc44fe88a7246b6213b")
	_, pubkey := key.Pubkey()
	fmt.Println(utils.BytesToHex(pubkey))

	message, _ := utils.HexToBytes("0xacba4329945ecb0e4f1db924e48a7ab27db75f36346f6b2b88e70d49a9cadeb2")
	sig := key.Sign(message)
	recoveredPubkey := key.RecoverPubkey(message, sig)
	hexRecoveredPubkey := utils.BytesToHex(recoveredPubkey[1:])
	fmt.Println(hexRecoveredPubkey)

	// Output:
	// 0009455d20f00e6a944017377122412b927c23e85bd4da670ac619217a9de67b393c74fd78be4a30cec529505f11408cdc42a81a9bf8f08584b6c39cb9fc1783
	// 0009455d20f00e6a944017377122412b927c23e85bd4da670ac619217a9de67b393c74fd78be4a30cec529505f11408cdc42a81a9bf8f08584b6c39cb9fc1783

}
