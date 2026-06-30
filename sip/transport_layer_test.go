package sip

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/fakes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testRawOptions(callID string) []byte {
	return []byte("OPTIONS sip:example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-test\r\n" +
		"From: <sip:alice@example.com>;tag=from1\r\n" +
		"To: <sip:bob@example.com>\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n")
}

func TestTransportLayerClosing(t *testing.T) {
	// NOTE it creates real network connection

	// TODO add other transports
	for _, tran := range []string{"UDP"} {
		t.Run(tran, func(t *testing.T) {
			tp := NewTransportLayer(net.DefaultResolver, NewParser(), nil)
			req := NewRequest(OPTIONS, Uri{Host: "localhost", Port: 5066})
			req.AppendHeader(&ViaHeader{Host: "127.0.0.1", Port: 0})

			conn, err := tp.ClientRequestConnection(context.TODO(), req)
			require.NoError(t, err)

			tp.Close()
			c := conn.(*UDPConnection)
			require.Error(t, c.Close(), "It is not closed already")
		})
	}
}

func TestTransportLayerReadFilterUDP(t *testing.T) {
	filterCalls := make(chan TransportReadProps, 2)
	tp := NewTransportLayer(net.DefaultResolver, NewParser(), nil, WithTransportLayerReadFilter(
		func(info TransportReadProps, data []byte) ([]byte, error) {
			filterCalls <- info
			if bytes.Contains(data, []byte("drop-call")) {
				return nil, nil
			}

			return bytes.ReplaceAll(data, []byte("bad-call"), []byte("good-call")), nil
		},
	))
	defer tp.Close()

	msgs := make(chan Message, 1)
	tp.OnMessage(func(msg Message) {
		msgs <- msg
	})

	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer serverConn.Close()

	go func() {
		_ = tp.ServeUDP(serverConn)
	}()

	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer clientConn.Close()

	serverAddr, err := net.ResolveUDPAddr("udp", serverConn.LocalAddr().String())
	require.NoError(t, err)

	_, err = clientConn.WriteTo(testRawOptions("drop-call"), serverAddr)
	require.NoError(t, err)
	_, err = clientConn.WriteTo(testRawOptions("bad-call"), serverAddr)
	require.NoError(t, err)

	var msg Message
	select {
	case msg = <-msgs:
	case <-time.After(2 * time.Second):
		t.Fatal("expected filtered UDP message")
	}

	require.Equal(t, "good-call", msg.CallID().Value())
	require.Equal(t, "UDP", msg.Transport())
	require.Equal(t, clientConn.LocalAddr().String(), msg.Source())

	var info TransportReadProps
	select {
	case info = <-filterCalls:
	case <-time.After(2 * time.Second):
		t.Fatal("expected UDP filter call")
	}
	require.Equal(t, "UDP", info.Transport)
	require.Equal(t, serverConn.LocalAddr().String(), info.LocalAddr.String())
	require.Equal(t, clientConn.LocalAddr().String(), info.RemoteAddr.String())
}

func TestTransportLayerReadFilterTCPErrorStopsRead(t *testing.T) {
	filterErr := errors.New("stop read")
	filterCalls := make(chan TransportReadProps, 1)
	tcp := &TransportTCP{
		readFilter: func(info TransportReadProps, data []byte) ([]byte, error) {
			filterCalls <- info
			return nil, filterErr
		},
	}
	tcp.init(NewParser())

	closed := make(chan struct{})
	tcp.onConnClose = func(conn Connection) {
		close(closed)
	}

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	conn := &TCPConnection{
		Conn:     serverConn,
		refcount: 1,
	}

	go tcp.readConnection(conn, serverConn.LocalAddr().String(), serverConn.RemoteAddr().String(), func(msg Message) {
		t.Fatal("handler should not be called after read filter error")
	})

	_, err := clientConn.Write(testRawOptions("error-call"))
	require.NoError(t, err)

	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("expected TCP read connection to stop")
	}

	select {
	case info := <-filterCalls:
		require.Equal(t, "TCP", info.Transport)
		require.NotNil(t, info.LocalAddr)
		require.NotNil(t, info.RemoteAddr)
	case <-time.After(2 * time.Second):
		t.Fatal("expected TCP filter call")
	}
}

func TestTransportLayerTCPFramingErrorClosesConnection(t *testing.T) {
	tcp := &TransportTCP{}
	tcp.init(NewParser())

	closed := make(chan struct{})
	tcp.onConnClose = func(conn Connection) {
		close(closed)
	}

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	conn := &TCPConnection{
		Conn:     serverConn,
		refcount: 1,
	}

	msgs := make(chan Message, 1)
	go tcp.readConnection(conn, serverConn.LocalAddr().String(), serverConn.RemoteAddr().String(), func(msg Message) {
		msgs <- msg
	})

	// Missing Content-Length on a stream transport is a framing error (RFC 3261 7.5).
	cancel := []byte("CANCEL sip:bob@example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-framing\r\n" +
		"From: <sip:alice@example.com>;tag=from1\r\n" +
		"To: <sip:bob@example.com>\r\n" +
		"Call-ID: framing-err\r\n" +
		"CSeq: 1 CANCEL\r\n" +
		"\r\n")
	_, err := clientConn.Write(cancel)
	require.NoError(t, err)

	select {
	case <-closed:
	case msg := <-msgs:
		t.Fatalf("handler called with %q, expected connection close", msg.String())
	case <-time.After(2 * time.Second):
		t.Fatal("expected framing error to close the TCP read connection")
	}
}

func TestTransportLayerClientConnectionReuse(t *testing.T) {
	// NOTE it creates real network connection
	tp := NewTransportLayer(net.DefaultResolver, NewParser(), nil)
	defer func() {
		require.Empty(t, tp.udp.pool.Size())
	}()
	defer func() {
		require.NoError(t, tp.Close())
	}()
	require.True(t, tp.connectionReuse)

	t.Run("Default", func(t *testing.T) {
		req := NewRequest(OPTIONS, Uri{Host: "localhost", Port: 5066})
		req.AppendHeader(&ViaHeader{Host: "127.0.0.1", Port: 0})

		conn, err := tp.ClientRequestConnection(context.TODO(), req)
		require.NoError(t, err)

		req = NewRequest(OPTIONS, Uri{Host: "localhost", Port: 5066})
		req.AppendHeader(&ViaHeader{Host: "127.0.0.1", Port: 0})

		conn2, err := tp.ClientRequestConnection(context.TODO(), req)
		require.NoError(t, err)

		// Compare by identity, not DeepEqual: the underlying *net.UDPConn has a
		// live reader goroutine mutating internal/poll.FD atomics concurrently.
		require.Same(t, conn, conn2)
	})

	t.Run("WithClientHostPort", func(t *testing.T) {
		req := NewRequest(OPTIONS, Uri{Host: "localhost", Port: 5066})
		req.AppendHeader(&ViaHeader{Host: "localhost", Port: 12345})
		req.Laddr = testCreateAddr(t, "127.0.0.1:12345")

		conn, err := tp.ClientRequestConnection(context.TODO(), req)
		require.NoError(t, err)

		req = NewRequest(OPTIONS, Uri{Host: "localhost", Port: 5066})
		req.AppendHeader(&ViaHeader{Host: "localhost", Port: 12345})
		req.Laddr = testCreateAddr(t, "127.0.0.1:12345")

		conn2, err := tp.ClientRequestConnection(context.TODO(), req)
		require.NoError(t, err)
		require.Same(t, conn, conn2)

		// Now same destination but forcing port
		req = NewRequest(OPTIONS, Uri{Host: "localhost", Port: 5066})
		req.AppendHeader(&ViaHeader{Host: "127.0.0.1", Port: 9876})
		req.Laddr = testCreateAddr(t, "127.0.0.1:9876")
		conn3, err := tp.ClientRequestConnection(context.TODO(), req)

		require.NoError(t, err)
		require.NotSame(t, conn, conn3)
	})

	testParallel := func(t *testing.T, transport string) {
		req := NewRequest(OPTIONS, Uri{Host: "localhost", Port: 5066})
		req.AppendHeader(&ViaHeader{Host: "127.0.0.1", Port: 0})
		req.SetTransport(transport)
		connections := sync.Map{}
		wg := sync.WaitGroup{}

		for i := range 10 {
			wg.Add(1)
			go func(req *Request) {
				defer wg.Done()
				conn, err := tp.ClientRequestConnection(context.TODO(), req)
				t.Log("Created connect", conn.LocalAddr().String())
				require.NoError(t, err)
				connections.Store(i, conn)
			}(req.Clone())
		}

		wg.Wait()
		connFirst, _ := connections.Load(0)
		connections.Range(func(key, value any) bool {
			assert.Same(t, connFirst, value)
			return true
		})
	}

	t.Run("ParallelUDP", func(t *testing.T) {
		testParallel(t, "UDP")
	})
	t.Run("ParallelTCP", func(t *testing.T) {
		l, err := net.Listen("tcp4", "127.0.0.1:5066")
		require.NoError(t, err)
		defer l.Close()
		go func() {
			for {
				conn, err := l.Accept()
				if err != nil {
					break
				}
				go func() { conn.Read([]byte{}) }()
			}
		}()
		testParallel(t, "TCP")
	})

}

func TestTransportLayerClientConnectionFlowAffinity(t *testing.T) {
	// RFC 5923: in-dialog requests over a reliable transport must reuse the
	// connection established for the dialog, which is pooled under the peer
	// (source) address rather than the Route derived destination.
	tp := NewTransportLayer(net.DefaultResolver, NewParser(), nil)
	defer func() {
		require.NoError(t, tp.Close())
	}()

	// Simulate an inbound accepted connection pooled under the peer source addr.
	const sourceKey = "10.0.0.5:5061"
	pinnedConn := &TCPConnection{Conn: &fakes.TCPConn{
		LAddr: net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5060},
		RAddr: net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 5061},
	}}
	tp.tcp.pool.Add(sourceKey, pinnedConn)
	// Remove the fake from the pool so Close does not act on it.
	defer tp.tcp.pool.Delete(sourceKey)

	t.Run("ReusesPinnedConnection", func(t *testing.T) {
		// Destination is the Route hop (TEST-NET-1, unroutable). A real dial
		// would fail, so reaching the pinned connection proves no dial happened.
		req := NewRequest(OPTIONS, Uri{Host: "192.0.2.1", Port: 5061})
		req.AppendHeader(&ViaHeader{Host: "127.0.0.1", Port: 0})
		req.SetTransport("tcp")
		req.SetConnectionFlowAddr(sourceKey)

		conn, err := tp.ClientRequestConnection(context.TODO(), req)
		require.NoError(t, err)
		require.Same(t, pinnedConn, conn)
	})

	t.Run("FallsBackWhenConnectionGone", func(t *testing.T) {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)
		defer l.Close()
		go func() {
			for {
				conn, err := l.Accept()
				if err != nil {
					break
				}
				go func() { conn.Read([]byte{}) }()
			}
		}()

		host, port, err := net.SplitHostPort(l.Addr().String())
		require.NoError(t, err)
		dport, err := strconv.Atoi(port)
		require.NoError(t, err)

		req := NewRequest(OPTIONS, Uri{Host: host, Port: dport})
		req.AppendHeader(&ViaHeader{Host: "127.0.0.1", Port: 0})
		req.SetTransport("tcp")
		// Flow addr that is not in the pool: must fall back to a fresh dial.
		req.SetConnectionFlowAddr("10.0.0.99:5061")

		conn, err := tp.ClientRequestConnection(context.TODO(), req)
		require.NoError(t, err)
		require.NotNil(t, conn)
		require.NotSame(t, pinnedConn, conn)
	})
}

// selfSignedTLSCert returns a self-signed leaf (used as its own root) covering
// the given DNS SANs and no IP SAN, plus a pool trusting it.
func selfSignedTLSCert(t *testing.T, dnsNames ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: dnsNames[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, roots
}

func TestTransportLayerClientTLSHostnameOverride(t *testing.T) {
	// Reproduces the carrier teardown scenario: a TLS peer presents a
	// hostname-only certificate (no IP SAN). An in-dialog request is routed to
	// the peer Contact, a bare IP. Re-dialing that IP defaults SNI to the IP and
	// fails verification; pinning the dialog hostname via connTLSHostname makes
	// the handshake verify while still dialing the specific IP.
	const sni = "carrier.example.com"

	// Self-signed leaf with a DNS SAN and no IP SAN.
	serverCert, roots := selfSignedTLSCert(t, sni)

	// TLS server bound to a loopback IP, which the certificate does not cover.
	ln, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{serverCert}})
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = conn.(*tls.Conn).Handshake() }()
		}
	}()

	host, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	dport, err := strconv.Atoi(port)
	require.NoError(t, err)

	newReq := func() *Request {
		req := NewRequest(OPTIONS, Uri{Scheme: "sips", Host: host, Port: dport})
		req.AppendHeader(&ViaHeader{Host: "127.0.0.1", Port: 0})
		req.SetTransport("tls")
		return req
	}

	t.Run("WithoutHostnameFailsVerification", func(t *testing.T) {
		tp := NewTransportLayer(net.DefaultResolver, NewParser(), &tls.Config{RootCAs: roots})
		defer tp.Close()

		_, err := tp.ClientRequestConnection(context.TODO(), newReq())
		require.Error(t, err)
		require.Contains(t, err.Error(), "certificate")
	})

	t.Run("WithHostnameVerifies", func(t *testing.T) {
		tp := NewTransportLayer(net.DefaultResolver, NewParser(), &tls.Config{RootCAs: roots})
		defer tp.Close()

		req := newReq()
		req.SetConnectionTLSHostname(sni)

		conn, err := tp.ClientRequestConnection(context.TODO(), req)
		require.NoError(t, err)
		require.NotNil(t, conn)

		// The hostname override is SNI only: the connection is still pooled under
		// the dialed IP, never under the hostname.
		require.NotNil(t, tp.tls.pool.getUnref(net.JoinHostPort(host, port)))
		require.Nil(t, tp.tls.pool.getUnref(net.JoinHostPort(sni, port)))
	})
}

func TestTransportLayerClientTLSHostnameNotOverriddenForFQDN(t *testing.T) {
	// Regression guard for the unconditional override: connTLSHostname must only
	// substitute SNI when the in-dialog destination is a bare IP with no usable
	// SNI of its own. When the destination is itself a hostname, resolveRemoteAddr
	// already produced the correct ServerName, and clobbering it with the dialog
	// hostname would break a legitimate re-dial to a different host whose
	// certificate does not cover the dialog hostname.
	const dialogHost = "carrier.example.com" // pinned, NOT on the server cert

	// Cert covers only the destination hostname (localhost), not the dialog host.
	serverCert, roots := selfSignedTLSCert(t, "localhost")

	ln, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{serverCert}})
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = conn.(*tls.Conn).Handshake() }()
		}
	}()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	dport, err := strconv.Atoi(port)
	require.NoError(t, err)

	tp := NewTransportLayer(net.DefaultResolver, NewParser(), &tls.Config{RootCAs: roots})
	defer tp.Close()

	// Destination host is a hostname (localhost) resolving to the loopback
	// listener; pin a different dialog hostname the cert does not cover.
	req := NewRequest(OPTIONS, Uri{Scheme: "sips", Host: "localhost", Port: dport})
	req.AppendHeader(&ViaHeader{Host: "127.0.0.1", Port: 0})
	req.SetTransport("tls")
	req.SetConnectionTLSHostname(dialogHost)

	// The gate keeps SNI = localhost (the destination), so the handshake verifies.
	// Without the gate SNI would be carrier.example.com and verification would fail.
	conn, err := tp.ClientRequestConnection(context.TODO(), req)
	require.NoError(t, err)
	require.NotNil(t, conn)

	// Pool is keyed by the dialed IP, never the pinned dialog hostname.
	require.Nil(t, tp.tls.pool.getUnref(net.JoinHostPort(dialogHost, port)))
}

func TestTransportLayerClientConnectionNoReuse(t *testing.T) {
	// NOTE it creates real network connection
	tp := NewTransportLayer(net.DefaultResolver, NewParser(), nil, WithTransportLayerConnectionReuse(false))
	defer func() {
		require.Empty(t, tp.udp.pool.Size())
	}()
	defer func() {
		require.NoError(t, tp.Close())
	}()

	t.Run("Default", func(t *testing.T) {
		req := NewRequest(OPTIONS, Uri{Host: "localhost", Port: 5066})
		req.AppendHeader(&ViaHeader{Host: "127.0.0.1", Port: 0})

		conn, err := tp.ClientRequestConnection(context.TODO(), req)
		require.NoError(t, err)

		req = NewRequest(OPTIONS, Uri{Host: "localhost", Port: 5066})
		req.AppendHeader(&ViaHeader{Host: "127.0.0.1", Port: 0})

		conn2, err := tp.ClientRequestConnection(context.TODO(), req)
		require.NoError(t, err)

		require.NotSame(t, conn, conn2)
	})

	t.Run("WithClientHostPort", func(t *testing.T) {
		req := NewRequest(OPTIONS, Uri{Host: "localhost", Port: 5066})
		req.AppendHeader(&ViaHeader{Host: "127.0.0.1", Port: 12345})
		req.Laddr = testCreateAddr(t, "127.0.0.1:12345")

		conn, err := tp.ClientRequestConnection(context.TODO(), req)
		require.NoError(t, err)

		req = NewRequest(OPTIONS, Uri{Host: "localhost", Port: 5066})
		req.AppendHeader(&ViaHeader{Host: "127.0.0.1", Port: 12345})
		req.Laddr = testCreateAddr(t, "127.0.0.1:12345")

		conn2, err := tp.ClientRequestConnection(context.TODO(), req)
		require.NoError(t, err)
		require.Same(t, conn, conn2)

		// Now same destination but forcing port
		req = NewRequest(OPTIONS, Uri{Host: "localhost", Port: 5066})
		req.AppendHeader(&ViaHeader{Host: "127.0.0.1", Port: 9876})
		req.Laddr = testCreateAddr(t, "127.0.0.1:9876")
		conn3, err := tp.ClientRequestConnection(context.TODO(), req)
		require.NoError(t, err)

		require.NotSame(t, conn, conn3)
	})
}

func TestTransportLayerDefaultPort(t *testing.T) {
	// NOTE it creates real network connection

	// TODO add other transports
	for _, tran := range []string{"UDP"} {
		t.Run(tran, func(t *testing.T) {
			tp := NewTransportLayer(net.DefaultResolver, NewParser(), nil)
			req := NewRequest(OPTIONS, Uri{Host: "127.0.0.99"})
			req.AppendHeader(&ViaHeader{Host: "127.0.0.1", Port: 0})

			_, err := tp.ClientRequestConnection(context.TODO(), req)
			require.NoError(t, err)

			tp.Close()
			require.Equal(t, "127.0.0.99:5060", req.Destination())
		})
	}
}

func TestTransportLayerResolving(t *testing.T) {
	// NOTE it creates real network connection

	tp := NewTransportLayer(net.DefaultResolver, NewParser(), nil)
	addr := Addr{}
	err := tp.resolveAddr(context.TODO(), "udp", "localhost", "sip", &addr)
	require.NoError(t, err)

	assert.True(t, addr.IP.To4() != nil)
	assert.Equal(t, "127.0.0.1:0", addr.String())
}
