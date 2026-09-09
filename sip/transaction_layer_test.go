package sip

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo/fakes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransactionLayerRequestPanic(t *testing.T) {
	for _, transport := range []string{"UDP", "TCP"} {
		for _, tc := range []struct {
			name      string
			method    RequestMethod
			status    int
			terminate bool
			want      int
		}{
			{name: "invite", method: INVITE, want: 500},
			{name: "provisional", method: INVITE, status: 180, want: 500},
			{name: "final_error", method: INVITE, status: 486, want: 486},
			{name: "final_success", method: INVITE, status: 200, want: 200},
			{name: "options", method: OPTIONS, want: 500},
			{name: "terminated", method: INVITE, terminate: true},
			{name: "ack", method: ACK},
			{name: "cancel", method: CANCEL},
			{name: "answered_cancel", method: CANCEL, status: 200, want: 200},
		} {
			t.Run(transport+"/"+tc.name, func(t *testing.T) {
				var output, diagnostics panicTestBuffer
				logger := slog.New(slog.NewTextHandler(&diagnostics, &slog.HandlerOptions{Level: slog.LevelError}))
				tp := NewTransportLayer(net.DefaultResolver, NewParser(), nil)
				defer tp.Close()
				txl := NewTransactionLayer(tp, WithTransactionLayerLogger(logger))
				defer txl.Close()
				const peer = "127.0.0.1:5061"
				conn := &TCPConnection{Conn: &fakes.TCPConn{Writer: &output}}
				pool := tp.tcp.pool
				if transport == "UDP" {
					pool = tp.udp.pool
				}
				pool.Add(peer, conn)
				req := testCreateRequest(t, string(tc.method), "sip:secret@example.com", transport, peer)
				req.CSeq().MethodName = tc.method
				req.SetSource(peer)
				req.SetBody([]byte("secret-sdp-key"))
				var handled *ServerTx
				txl.OnRequest(func(req *Request, tx *ServerTx) {
					handled = tx
					if tc.status != 0 {
						require.NoError(t, tx.Respond(NewResponseFromRequest(req, tc.status, "Test response", nil)))
					}
					if tc.terminate {
						tx.Terminate()
					}
					panic("secret-panic-value")
				})
				// The same entry point handleMessage launches for transport requests.
				done := make(chan struct{})
				go func() {
					defer close(done)
					txl.handleRequestBackground(req)
				}()
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("panicking handler did not finish")
				}
				require.NotNil(t, handled)
				require.Contains(t, diagnostics.String(), "SIP request handler panic")
				require.NotContains(t, diagnostics.String(), "secret")
				if tc.want == 0 {
					require.Empty(t, output.String())
				} else {
					require.Contains(t, output.String(), "SIP/2.0 "+strconv.Itoa(tc.want))
					if tc.want != 500 {
						require.NotContains(t, output.String(), "SIP/2.0 500")
					}
				}
				if transport == "UDP" && (tc.method == INVITE || tc.method == OPTIONS) && !tc.terminate {
					handled.fsmMu.Lock()
					cachedStatus := handled.fsmResp.StatusCode
					handled.fsmMu.Unlock()
					require.Equal(t, tc.want, cachedStatus, "final response cache must survive recovery")
					if tc.want >= 300 {
						before := len(output.String())
						require.NoError(t, handled.Receive(req))
						require.Contains(t, output.String()[before:], "SIP/2.0 "+strconv.Itoa(tc.want))
					}
				} else {
					select {
					case <-handled.Done():
					default:
						t.Fatal("recovered transaction leaked")
					}
				}
				// An independent transaction still reaches the handler and responds.
				txl.OnRequest(func(req *Request, tx *ServerTx) {
					require.NoError(t, tx.Respond(NewResponseFromRequest(req, StatusOK, "OK", nil)))
					tx.TerminateGracefully()
				})
				control := testCreateRequest(t, "OPTIONS", "sip:control@example.com", transport, peer)
				control.CSeq().MethodName = OPTIONS
				control.SetSource(peer)
				txl.handleRequestBackground(control)
				require.Contains(t, output.String(), "SIP/2.0 200 OK")
			})
		}
	}
}

type panicTestBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *panicTestBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *panicTestBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func testCreateAddr(t *testing.T, addr string) Addr {
	a := Addr{}
	require.NoError(t, a.parseAddr(addr))
	return a
}

func TestIntegrationTransactionLayerServerTx(t *testing.T) {
	if os.Getenv("TEST_INTEGRATION") == "" {
		t.Skip("Use TEST_INTEGRATION env value to run this test")
		return
	}

	tp := NewTransportLayer(net.DefaultResolver, NewParser(), nil)
	txl := NewTransactionLayer(tp)

	req := testCreateRequest(t, "OPTIONS", "sip:192.168.0.1", "UDP", "127.0.0.1:15069")
	key, _ := ServerTxKeyMake(req)

	var count int32 = 0
	txl.OnRequest(func(req *Request, tx *ServerTx) {
		atomic.AddInt32(&count, 1)
		t.Log("Request")
	})

	// Connection will be created
	err := txl.handleRequest(req)
	require.NoError(t, err)

	// Now create connection and test multiple concurent received request
	tp.udp.CreateConnection(context.TODO(),
		testCreateAddr(t, "127.0.0.1:15069"),
		testCreateAddr(t, "192.168.0.1:1234"),
		tp.handleMessage,
	)

	wg := sync.WaitGroup{}
	wg.Add(3)
	for range []int{0, 1, 2} {
		go func() {
			defer wg.Done()
			err := txl.handleRequest(req)
			if err != nil {
				t.Log("Request failed with err", err)
			}
		}()
	}

	wg.Wait()
	require.EqualValues(t, 1, atomic.LoadInt32(&count))
	require.EqualValues(t, 1, len(txl.serverTransactions.items))

	// After termination of transaction, it  must be removed from list
	tx := txl.serverTransactions.items[key]
	require.NotNil(t, tx)
	tx.Terminate()
	require.EqualValues(t, 0, len(txl.serverTransactions.items))
}

func TestTransactionLayerMalformedRequestStateless400(t *testing.T) {
	if os.Getenv("TEST_INTEGRATION") == "" {
		t.Skip("Use TEST_INTEGRATION env value to run this test")
		return
	}

	// Listen on a UDP port to receive the stateless 400 response.
	receiverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)
	receiverConn, err := net.ListenUDP("udp", receiverAddr)
	require.NoError(t, err)
	defer receiverConn.Close()
	receiverActualAddr := receiverConn.LocalAddr().String()

	// Set up the transaction layer with a real transport.
	tp := NewTransportLayer(net.DefaultResolver, NewParser(), nil)
	txl := NewTransactionLayer(tp)

	var handlerCalled int32
	txl.OnRequest(func(req *Request, tx *ServerTx) {
		atomic.AddInt32(&handlerCalled, 1)
	})

	// Create a UDP connection in the transport pool so WriteMsg can find it.
	localAddr := "127.0.0.1:15071"
	_, err = tp.udp.CreateConnection(
		context.TODO(),
		testCreateAddr(t, localAddr),
		testCreateAddr(t, receiverActualAddr),
		tp.handleMessage,
	)
	require.NoError(t, err)

	// Build a malformed request: valid Via, From, To, Call-ID, but NO CSeq.
	raw := strings.Join([]string{
		"REGISTER sip:192.168.100.30:5060 SIP/2.0",
		"Via: SIP/2.0/UDP " + receiverActualAddr + ";branch=z9hG4bK-test123",
		"From: <sip:alice@example.com>;tag=from1",
		"To: <sip:alice@example.com>",
		"Call-ID: malformed-test-call-id",
		"Content-Length: 0",
		"",
		"",
	}, "\r\n")

	msg, err := ParseMessage([]byte(raw))
	require.NoError(t, err)

	req := msg.(*Request)
	req.SetTransport("UDP")
	req.SetSource(receiverActualAddr)

	// handleRequest should return an error because CSeq is missing.
	err = txl.handleRequest(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CSeq")

	// The request handler should NOT have been called.
	assert.EqualValues(t, 0, atomic.LoadInt32(&handlerCalled))

	// Read the stateless 400 response that should have been sent.
	buf := make([]byte, 4096)
	receiverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, readErr := receiverConn.ReadFromUDP(buf)
	require.NoError(t, readErr, "expected to receive a stateless 400 response")

	respMsg, err := ParseMessage(buf[:n])
	require.NoError(t, err)

	resp, ok := respMsg.(*Response)
	require.True(t, ok, "expected a SIP response")
	assert.Equal(t, 400, resp.StatusCode)
	assert.Equal(t, "Bad Request", resp.Reason)
}

func TestTransactionLayerClientTx(t *testing.T) {
	if os.Getenv("TEST_INTEGRATION") == "" {
		t.Skip("Use TEST_INTEGRATION env value to run this test")
		return
	}
	tp := NewTransportLayer(net.DefaultResolver, NewParser(), nil)
	txl := NewTransactionLayer(tp)

	req := testCreateRequest(t, "OPTIONS", "sip:127.0.0.1:9876", "UDP", "127.0.0.1:15070")

	wg := sync.WaitGroup{}
	wg.Add(3)
	var count int32
	for range []int{0, 1, 2} {
		go func() {
			defer wg.Done()
			tx, err := txl.Request(context.TODO(), req)
			if err != nil {
				t.Log("Request failed with err", err)
				return
			}
			atomic.AddInt32(&count, 1)
			require.Equal(t, req, tx.origin)
		}()
	}

	wg.Wait()
	// Only one transaction will be created and executed
	require.EqualValues(t, 1, atomic.LoadInt32(&count))
	require.Equal(t, 2, tp.udp.pool.Size())
	assert.True(t, tp.udp.pool.Get("127.0.0.1:9876") != nil)
}
