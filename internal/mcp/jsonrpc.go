package mcp

import (
	"encoding/json"
	"errors"
)

// JSON-RPC 2.0 error codes (https://www.jsonrpc.org/specification)
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603

	// MCP 自定义错误码（在 -32000 ~ -32099 服务端错误段内）
	CodeUnauthorized      = -32001
	CodeForbidden         = -32002
	CodeRateLimited       = -32003
	CodeToolExecution     = -32010
	CodeRequiresConfirm   = -32011
	CodeResourceNotFound  = -32020
	CodeUnsupportedProto  = -32030
)

// Request JSON-RPC 2.0 请求。ID 为空时表示 notification（不需要响应）。
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response JSON-RPC 2.0 响应。
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError JSON-RPC 错误对象。
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// NewError 构造一个 RPCError。
func NewError(code int, message string) *RPCError {
	return &RPCError{Code: code, Message: message}
}

// NewErrorWithData 构造带 data 字段的 RPCError。
func NewErrorWithData(code int, message string, data any) *RPCError {
	raw, _ := json.Marshal(data)
	return &RPCError{Code: code, Message: message, Data: raw}
}

// IsNotification 判断请求是否为 notification（无 ID）。
func (r *Request) IsNotification() bool {
	return len(r.ID) == 0 || string(r.ID) == "null"
}

// ParseRequest 从原始 JSON 解析单条 JSON-RPC 请求。
// 仅支持单条请求（MCP Streamable HTTP 当前规范允许，但不强制 batch）。
func ParseRequest(data []byte) (*Request, error) {
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, err
	}
	if req.JSONRPC != "2.0" {
		return nil, errors.New("invalid jsonrpc version")
	}
	if req.Method == "" {
		return nil, errors.New("empty method")
	}
	return &req, nil
}

// NewResponse 构造成功响应。
func NewResponse(id json.RawMessage, result any) *Response {
	raw, _ := json.Marshal(result)
	return &Response{JSONRPC: "2.0", ID: id, Result: raw}
}

// NewErrorResponse 构造错误响应。
func NewErrorResponse(id json.RawMessage, err *RPCError) *Response {
	return &Response{JSONRPC: "2.0", ID: id, Error: err}
}
