package utils

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

func Trim0x(h string) string {
	return strings.TrimPrefix(h, "0x")
}

func BytesTo0xHex(b []byte) string {
	return fmt.Sprintf("0x%s", hex.EncodeToString(b))
}

func BytesToHex(b []byte) string {
	return hex.EncodeToString(b)
}

func HexToBytes(h string) ([]byte, error) {
	if strings.Contains(h, "0x") {
		return hexutil.Decode(h)
	}
	return hexutil.Decode(fmt.Sprintf("0x%s", h))
}
