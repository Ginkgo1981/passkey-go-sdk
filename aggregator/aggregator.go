package aggregator

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/ginkgo981/pass-sdk-go/crypto/alg"
	"github.com/ginkgo981/pass-sdk-go/utils"
	"github.com/nervosnetwork/ckb-sdk-go/v2/address"
)

type ExtensionSubKeyResult struct {
	ExtensionSmtEntry string `json:"extension_smt_entry"`
	SmtRootHash       string `json:"smt_root_hash"`
	BlockNumber       uint64 `json:"block_number"`
}

type ExtensionSubKeyResp struct {
	Result ExtensionSubKeyResult `json:"result"`
	Error  rpcError              `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type RPCClient struct {
	url    string
	client *http.Client
}

type request struct {
	Id      int                    `json:"id"`
	JsonRpc string                 `json:"jsonrpc"`
	Method  string                 `json:"method"`
	Params  map[string]interface{} `json:"params"`
}

func NewRPCClient(url string) *RPCClient {
	return &RPCClient{
		url:    url,
		client: &http.Client{},
	}
}

func (rpc *RPCClient) GetExtensionSubKeySmt(address *address.Address, pubkeyHash []byte, algIndex alg.AlgIndex, extData uint32) (*ExtensionSubKeyResult, error) {
	subkey := make(map[string]interface{})
	subkey["ext_data"] = extData
	subkey["alg_index"] = algIndex
	subkey["pubkey_hash"] = utils.BytesTo0xHex(pubkeyHash)

	params := make(map[string]interface{})
	params["lock_script"] = utils.BytesTo0xHex(address.Script.Serialize())
	params["ext_action"] = "0xF0"
	params["subkeys"] = []interface{}{subkey}

	req := request{
		Id:      1,
		JsonRpc: "2.0",
		Method:  "generate_extension_subkey_smt",
		Params:  params,
	}

	jsonReq, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest(http.MethodPost, rpc.url, bytes.NewBuffer(jsonReq))

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := rpc.client.Do(httpReq)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		responseBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		var resp ExtensionSubKeyResp
		err = json.Unmarshal(responseBody, &resp)

		return &resp.Result, err
	}

	return nil, nil
}
