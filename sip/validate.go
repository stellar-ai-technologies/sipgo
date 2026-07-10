package sip

import (
	"fmt"
	"strings"
)

// ValidateRequest rejects carriage returns or line feeds in a request's start
// line and headers. These characters delimit SIP message lines, so accepting
// them from user-controlled fields would allow an extra header or message to be
// injected on the wire.
//
// The message body is deliberately not inspected because CR and LF are valid
// body bytes. Call ValidateRequest after building all request headers and before
// passing the request to a client, transaction, or transport.
func ValidateRequest(req *Request) error {
	if req == nil {
		return fmt.Errorf("validate request: request is nil")
	}
	return validateMessageLines("request", req.StartLine(), req.Headers())
}

// ValidateResponse rejects carriage returns or line feeds in a response's
// status line and headers. These characters delimit SIP message lines, so
// accepting them from user-controlled fields would allow an extra header or
// message to be injected on the wire.
//
// The message body is deliberately not inspected because CR and LF are valid
// body bytes. Call ValidateResponse after building all response headers and
// before passing the response to a transaction or transport.
func ValidateResponse(res *Response) error {
	if res == nil {
		return fmt.Errorf("validate response: response is nil")
	}
	return validateMessageLines("response", res.StartLine(), res.Headers())
}

func validateMessageLines(kind, startLine string, headers []Header) error {
	if strings.ContainsAny(startLine, "\r\n") {
		return fmt.Errorf("invalid CRLF in %s start line", kind)
	}

	for _, header := range headers {
		if strings.ContainsAny(header.Name(), "\r\n") {
			return fmt.Errorf("invalid CRLF in %s header name %q", kind, header.Name())
		}
		if strings.ContainsAny(header.Value(), "\r\n") {
			return fmt.Errorf("invalid CRLF in %s header %q", kind, header.Name())
		}
	}

	return nil
}
