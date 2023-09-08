package secp256r1

import (
	"fmt"
	"testing"

	"github.com/ginkgo981/pass-sdk-go/crypto/sha256"
	"github.com/ginkgo981/pass-sdk-go/utils"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	fmt.Println(len(key.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if key == nil {
		t.Fatal("key is nil")
	}
}

func ExampleImportKey() {
	key := ImportKey("0x4271c23380932c74a041b4f56779e5ef60e808a127825875f906260f1f657761")
	hexKey := utils.BytesTo0xHex(key.Bytes())
	fmt.Println(hexKey)

	// Output:
	// 0x4271c23380932c74a041b4f56779e5ef60e808a127825875f906260f1f657761
}

func ExamplePubKey() {
	key := ImportKey("0x4271c23380932c74a041b4f56779e5ef60e808a127825875f906260f1f657761")
	_, pubkey := key.Pubkey()
	hexKey := utils.BytesTo0xHex(pubkey)
	fmt.Println(hexKey)

	// Output:
	// 0x4599a5795423d54ab8e1f44f5c6ef5be9b1829beddb787bc732e4469d25f8c93e94afa393617f905bf1765c35dc38501a862b4b2f794a88b4f9010da02411a85
}

func TestVerifySignature1(t *testing.T) {
	key := ImportKey("0x4271c23380932c74a041b4f56779e5ef60e808a127825875f906260f1f657761")
	// message, _ := utils.HexToBytes("0x0fc4a3f69b91732a99e7d11aef8076e29ad1d88a4f3e")
	message := []byte("hello world")
	sig, _ := utils.HexToBytes("0x9d502b90a9104ca53e3e3a6563447f95a77455a1b7e468621651dcf64691c2e4a73cf4480fc680a6f7443cb8b15920df08a8e4065c1a5c80e7de8f83ead1951f")

	got := key.VerifySignature(sha256.Sha256(message), sig)

	want := true
	if got != want {
		t.Errorf("VerifiSignature() = %t, want %t", got, want)
	}
}

func ExampleSignMessage() {
	// 在椭圆曲线数字签名算法（如ECDSA）中，即使使用相同的私钥对相同的消息进行签名，生成的签名也会不同。这是因为在签名过程中会引入随机因子（random nonce）来增加签名的随机性，这个随机因子会影响最终的签名结果。
	key := ImportKey("0x4271c23380932c74a041b4f56779e5ef60e808a127825875f906260f1f657761")
	message := []byte("hello world")
	signature := key.Sign(sha256.Sha256(message))

	hexSig := utils.BytesTo0xHex(signature)
	fmt.Println(hexSig)

	// Output:
	//

}
