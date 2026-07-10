package sip

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateRequest(t *testing.T) {
	newRequest := func() *Request {
		req := NewRequest(REGISTER, Uri{User: "alice", Host: "example.com"})
		req.AppendHeader(NewHeader("Subject", "registration"))
		return req
	}

	t.Run("valid", func(t *testing.T) {
		req := newRequest()
		req.SetBody([]byte("body\r\nlines are allowed"))
		require.NoError(t, ValidateRequest(req))
	})

	t.Run("nil", func(t *testing.T) {
		require.Error(t, ValidateRequest(nil))
	})

	t.Run("start line", func(t *testing.T) {
		req := newRequest()
		req.Method = RequestMethod("REGISTER\r\nInjected")
		require.ErrorContains(t, ValidateRequest(req), "invalid CRLF")
	})

	t.Run("header name", func(t *testing.T) {
		req := newRequest()
		req.AppendHeader(NewHeader("X-Test\r\nInjected", "value"))
		require.ErrorContains(t, ValidateRequest(req), "invalid CRLF")
	})

	t.Run("header value", func(t *testing.T) {
		req := newRequest()
		req.AppendHeader(NewHeader("Subject", "injected\r\nContent-Length: 0"))
		require.ErrorContains(t, ValidateRequest(req), "invalid CRLF")
	})
}

func TestValidateResponse(t *testing.T) {
	newResponse := func() *Response {
		res := NewResponse(StatusOK, "OK")
		res.AppendHeader(NewHeader("Server", "sipgo"))
		return res
	}

	t.Run("valid", func(t *testing.T) {
		res := newResponse()
		res.SetBody([]byte("body\r\nlines are allowed"))
		require.NoError(t, ValidateResponse(res))
	})

	t.Run("nil", func(t *testing.T) {
		require.Error(t, ValidateResponse(nil))
	})

	t.Run("status line", func(t *testing.T) {
		res := newResponse()
		res.Reason = "OK\r\nInjected"
		require.ErrorContains(t, ValidateResponse(res), "invalid CRLF")
	})

	t.Run("header name", func(t *testing.T) {
		res := newResponse()
		res.AppendHeader(NewHeader("X-Test\r\nInjected", "value"))
		require.ErrorContains(t, ValidateResponse(res), "invalid CRLF")
	})

	t.Run("header value", func(t *testing.T) {
		res := newResponse()
		res.AppendHeader(NewHeader("Server", "injected\nContent-Length: 0"))
		require.ErrorContains(t, ValidateResponse(res), "invalid CRLF")
	})
}
