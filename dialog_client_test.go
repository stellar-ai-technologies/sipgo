package sipgo

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
	"github.com/emiago/sipgo/siptest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testClient(t testing.TB, f func(req *sip.Request) *sip.Response) *Client {
	ua, _ := NewUA()
	client, err := NewClient(ua)
	require.NoError(t, err)
	client.TxRequester = &siptest.ClientTxRequester{
		OnRequest: f,
	}
	return client
}

func testClientResponder(t testing.TB, f func(req *sip.Request, w *siptest.ClientTxResponder)) *Client {
	ua, _ := NewUA()
	client, err := NewClient(ua)
	require.NoError(t, err)
	client.TxRequester = &siptest.ClientTxRequesterResponder{
		OnRequest: f,
	}
	return client
}

func TestDialogClientRequestRecordRouteHeaders(t *testing.T) {
	client := testClient(t, func(req *sip.Request) *sip.Response {
		return sip.NewResponseFromRequest(req, 200, "OK", nil)
	})

	invite := sip.NewRequest(sip.INVITE, sip.Uri{User: "test", Host: "localhost"})
	invite.AppendHeader(sip.NewHeader("Contact", "<sip:uac@uac.p1.com>"))
	err := clientRequestBuildReq(client, invite)
	require.NoError(t, err)
	// assert.Equal(t, "localhost:5060", invite.Source())
	assert.Equal(t, "localhost:5060", invite.Destination())

	t.Run("LooseRouting", func(t *testing.T) {

		resp := sip.NewResponseFromRequest(invite, 200, "OK", nil)
		resp.AppendHeader(sip.NewHeader("Contact", "<sip:uas@uas.p2.com>"))
		// Fake some proxy headers
		resp.AppendHeader(sip.NewHeader("Record-Route", "<sip:p2.com;lr>"))
		resp.AppendHeader(sip.NewHeader("Record-Route", "<sip:p1.com;lr>"))

		s := DialogClientSession{
			UA: &DialogUA{
				Client: client,
			},
			Dialog: Dialog{
				InviteRequest:  invite,
				InviteResponse: resp,
			},
			inviteTx: sip.NewClientTx("test", invite, nil, slog.Default()),
		}
		// Send canceled request
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		ack := newAckRequestUAC(s.InviteRequest, s.InviteResponse, nil)
		assert.Equal(t, "uas.p2.com:5060", ack.Destination())
		s.WriteAck(ctx, ack)
		assert.Equal(t, "sip:uas@uas.p2.com", ack.Recipient.String())
		assert.Equal(t, "<sip:p1.com;lr>", ack.Route().Value())
		assert.Equal(t, "<sip:p2.com;lr>", ack.GetHeaders("Route")[1].Value())

		bye := newByeRequestUAC(s.InviteRequest, s.InviteResponse, nil)
		s.Do(ctx, bye)
		assert.Equal(t, "sip:uas@uas.p2.com", bye.Recipient.String())
		assert.Equal(t, "<sip:p1.com;lr>", bye.Route().Value())
		assert.Equal(t, "<sip:p2.com;lr>", bye.GetHeaders("Route")[1].Value())
	})

	t.Run("StrictRouting", func(t *testing.T) {

		resp := sip.NewResponseFromRequest(invite, 200, "OK", nil)
		resp.AppendHeader(sip.NewHeader("Contact", "<sip:uas@uas.p2.com>"))
		// Fake some proxy headers
		resp.AppendHeader(sip.NewHeader("Record-Route", "<sip:p2.com;lr>"))
		resp.AppendHeader(sip.NewHeader("Record-Route", "<sip:p1.com>"))

		s := DialogClientSession{
			UA: &DialogUA{
				Client: client,
			},
			Dialog: Dialog{
				InviteRequest:  invite,
				InviteResponse: resp,
			},
			inviteTx: sip.NewClientTx("test", invite, nil, slog.Default()),
		}

		// Send canceled request
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		ack := newAckRequestUAC(s.InviteRequest, s.InviteResponse, nil)
		assert.Equal(t, "uas.p2.com:5060", ack.Destination())
		s.WriteAck(ctx, ack)
		assert.Equal(t, "sip:p1.com", ack.Recipient.String())
		assert.Equal(t, "<sip:p1.com>", ack.Route().Value())
		assert.Equal(t, "<sip:p2.com;lr>", ack.GetHeaders("Route")[1].Value())

		bye := newByeRequestUAC(s.InviteRequest, s.InviteResponse, nil)
		s.Do(ctx, bye)
		assert.Equal(t, "sip:p1.com", bye.Recipient.String())
		assert.Equal(t, "<sip:p1.com>", bye.Route().Value())
		assert.Equal(t, "<sip:p2.com;lr>", bye.GetHeaders("Route")[1].Value())
	})

}

func TestDialogClientByeConnectionAffinity(t *testing.T) {
	// RFC 5923: in-dialog UAC requests over a reliable transport must be pinned
	// to the dialog's established connection (Layer 1, the INVITE *response*
	// source, which is the remote address the connection is pooled under) and,
	// when that connection is gone and a re-dial is needed, must present the
	// originally dialed hostname as TLS SNI (Layer 2) so a carrier Contact that
	// is a bare IP without an IP SAN still verifies.
	buildDialogReq := func(t *testing.T, transport, target string, newReq func(inv *sip.Request, resp *sip.Response) *sip.Request) *sip.Request {
		client := testClient(t, func(req *sip.Request) *sip.Response {
			return sip.NewResponseFromRequest(req, 200, "OK", nil)
		})

		invite, _, _ := createTestInvite(t, target, transport, "10.0.0.5:5061")
		resp := sip.NewResponseFromRequest(invite, 200, "OK", nil)
		resp.AppendHeader(&sip.ContactHeader{Address: sip.Uri{User: "service", Host: "54.172.60.2", Port: 5061}})
		// The 200 OK was read off the dialog connection, so its source is the
		// remote address that connection is pooled under.
		resp.SetSource("54.172.60.2:5061")

		s := DialogClientSession{
			UA:     &DialogUA{Client: client},
			Dialog: Dialog{InviteRequest: invite, InviteResponse: resp},
		}
		req := newReq(s.InviteRequest, s.InviteResponse)
		s.buildReq(req)
		return req
	}

	newBye := func(inv *sip.Request, resp *sip.Response) *sip.Request {
		return newByeRequestUAC(inv, resp, nil)
	}

	t.Run("TLS_FQDN", func(t *testing.T) {
		bye := buildDialogReq(t, "tls", "sips:service@customer.sip.twilio.com", newBye)
		require.Equal(t, "54.172.60.2:5061", bye.ConnectionFlowAddr())
		require.Equal(t, "customer.sip.twilio.com", bye.ConnectionTLSHostname())
	})

	t.Run("TLS_FQDN_ACK", func(t *testing.T) {
		// ACK is also built through buildReq and must carry the same pins.
		ack := buildDialogReq(t, "tls", "sips:service@customer.sip.twilio.com", func(inv *sip.Request, resp *sip.Response) *sip.Request {
			return newAckRequestUAC(inv, resp, nil)
		})
		require.Equal(t, "54.172.60.2:5061", ack.ConnectionFlowAddr())
		require.Equal(t, "customer.sip.twilio.com", ack.ConnectionTLSHostname())
	})

	t.Run("TCP_FQDN", func(t *testing.T) {
		bye := buildDialogReq(t, "tcp", "sip:service@customer.sip.twilio.com", newBye)
		require.Equal(t, "54.172.60.2:5061", bye.ConnectionFlowAddr())
		// Harmless for TCP; CreateConnection ignores it.
		require.Equal(t, "customer.sip.twilio.com", bye.ConnectionTLSHostname())
	})

	t.Run("UDP_NotReliable", func(t *testing.T) {
		bye := buildDialogReq(t, "udp", "sip:service@customer.sip.twilio.com", newBye)
		require.Equal(t, "", bye.ConnectionFlowAddr())
		require.Equal(t, "", bye.ConnectionTLSHostname())
	})

	t.Run("TLS_IPLiteral_NoHostname", func(t *testing.T) {
		// Dialog dialed an IP directly: no usable SNI, so do not pin a hostname.
		bye := buildDialogReq(t, "tls", "sips:service@54.172.60.2", newBye)
		require.Equal(t, "54.172.60.2:5061", bye.ConnectionFlowAddr())
		require.Equal(t, "", bye.ConnectionTLSHostname())
	})

	t.Run("TLS_IPv6Literal_NoHostname", func(t *testing.T) {
		bye := buildDialogReq(t, "tls", "sips:service@[2001:db8::1]", newBye)
		require.Equal(t, "", bye.ConnectionTLSHostname())
	})
}

func TestDialogClientMultiRequest(t *testing.T) {
	var sentReq *sip.Request
	client := testClient(t, func(req *sip.Request) *sip.Response {
		sentReq = req
		return sip.NewResponseFromRequest(req, 200, "OK", nil)
	})

	dua := DialogUA{
		Client: client,
	}
	d, err := dua.Invite(context.TODO(), sip.Uri{User: "test", Host: "localhost"}, nil)
	require.NoError(t, err)
	assert.NotNil(t, d.InviteRequest.From())
	assert.NotNil(t, d.InviteRequest.To())
	assert.NotNil(t, d.InviteRequest.Contact())
	assert.NotEmpty(t, d.InviteRequest.CallID())
	assert.NotEmpty(t, d.InviteRequest.MaxForwards())

	err = d.WaitAnswer(context.TODO(), AnswerOptions{})
	require.NoError(t, err)
	d.Ack(context.TODO())
	assert.Equal(t, d.InviteRequest.CSeq().SeqNo, sentReq.CSeq().SeqNo)

	_, err = d.Do(context.Background(), sip.NewRequest(sip.INVITE, sip.Uri{User: "reinvite", Host: "localhost"}))
	require.NoError(t, err)

	assert.Equal(t, d.InviteRequest.CSeq().SeqNo+1, sentReq.CSeq().SeqNo)
}

func TestDialogClientMultiResponses(t *testing.T) {

	t.Run("ProvisionalLoop", func(t *testing.T) {
		client := testClient(t, func(req *sip.Request) *sip.Response {
			return sip.NewResponseFromRequest(req, 100, "Trying", nil)
		})

		dua := DialogUA{
			Client: client,
		}
		d, err := dua.Invite(context.TODO(), sip.Uri{User: "test", Host: "localhost"}, nil)
		require.NoError(t, err)
		go func() {
			// Receive more provisional
			for i := 0; i < 10; i++ {
				d.inviteTx.(*sip.ClientTx).Receive(sip.NewResponseFromRequest(d.InviteRequest, 100, "Trying", nil))
			}
		}()
		err = d.WaitAnswer(context.TODO(), AnswerOptions{})
		require.Error(t, err)
	})
	t.Run("ProxyAuthLoop", func(t *testing.T) {
		var sentReq *sip.Request
		client := testClient(t, func(req *sip.Request) *sip.Response {
			sentReq = req
			res := sip.NewResponseFromRequest(req, 407, "Unauthorized", nil)
			challenge := `Digest username="user", realm="test", nonce="662d65a084b88c6d2a745a9de086fa91", uri="sip:+user@example.com", algorithm=sha-256, response="3681b63e5d9c3bb80e5350e2783d7b88"`
			res.AppendHeader(sip.NewHeader("Proxy-Authenticate", challenge))
			return res
		})

		dua := DialogUA{
			Client: client,
		}
		d, err := dua.Invite(context.TODO(), sip.Uri{User: "test", Host: "localhost"}, nil)
		require.NoError(t, err)

		err = d.WaitAnswer(context.TODO(), AnswerOptions{Password: "secret"})
		require.Error(t, err)
		assert.Equal(t, d.InviteRequest.CSeq().SeqNo, sentReq.CSeq().SeqNo)
	})

	t.Run("AuthLoop", func(t *testing.T) {
		var sentReq *sip.Request
		client := testClient(t, func(req *sip.Request) *sip.Response {
			sentReq = req
			res := sip.NewResponseFromRequest(req, 401, "Unauthorized", nil)
			challenge := `Digest username="user", realm="test", nonce="662d65a084b88c6d2a745a9de086fa91", uri="sip:+user@example.com", algorithm=sha-256, response="3681b63e5d9c3bb80e5350e2783d7b88"`
			res.AppendHeader(sip.NewHeader("WWW-Authenticate", challenge))
			return res
		})

		dua := DialogUA{
			Client: client,
		}
		d, err := dua.Invite(context.TODO(), sip.Uri{User: "test", Host: "localhost"}, nil)
		require.NoError(t, err)

		err = d.WaitAnswer(context.TODO(), AnswerOptions{Password: "secret"})
		require.Error(t, err)
		assert.Equal(t, d.InviteRequest.CSeq().SeqNo, sentReq.CSeq().SeqNo)
	})

	t.Run("ProxyAuthRechallenge", func(t *testing.T) {
		attempts := 0
		client := testClient(t, func(req *sip.Request) *sip.Response {
			attempts++
			if attempts == 3 {
				return sip.NewResponseFromRequest(req, 200, "OK", nil)
			}

			res := sip.NewResponseFromRequest(req, 407, "Proxy Authentication Required", nil)
			nonce, stale := "first", ""
			if attempts == 2 {
				nonce, stale = "second", `, stale=true`
			}
			challenge := `Digest realm="test", nonce="` + nonce + `", algorithm=MD5` + stale
			res.AppendHeader(sip.NewHeader("Proxy-Authenticate", challenge))
			return res
		})

		dua := DialogUA{Client: client}
		d, err := dua.Invite(context.TODO(), sip.Uri{User: "test", Host: "localhost"}, nil)
		require.NoError(t, err)
		require.NoError(t, d.WaitAnswer(context.TODO(), AnswerOptions{Username: "user", Password: "secret"}))
		assert.Equal(t, 3, attempts)
		auth := d.InviteRequest.GetHeaders("Proxy-Authorization")
		require.Len(t, auth, 1)
		assert.Contains(t, auth[0].Value(), `nonce="second"`)
	})

	t.Run("AuthRechallenge", func(t *testing.T) {
		attempts := 0
		client := testClient(t, func(req *sip.Request) *sip.Response {
			attempts++
			if attempts == 3 {
				return sip.NewResponseFromRequest(req, 200, "OK", nil)
			}

			res := sip.NewResponseFromRequest(req, 401, "Unauthorized", nil)
			nonce, stale := "first", ""
			if attempts == 2 {
				nonce, stale = "second", `, stale=true`
			}
			challenge := `Digest realm="test", nonce="` + nonce + `", algorithm=MD5` + stale
			res.AppendHeader(sip.NewHeader("WWW-Authenticate", challenge))
			return res
		})

		dua := DialogUA{Client: client}
		d, err := dua.Invite(context.TODO(), sip.Uri{User: "test", Host: "localhost"}, nil)
		require.NoError(t, err)
		require.NoError(t, d.WaitAnswer(context.TODO(), AnswerOptions{Username: "user", Password: "secret"}))
		assert.Equal(t, 3, attempts)
		auth := d.InviteRequest.GetHeaders("Authorization")
		require.Len(t, auth, 1)
		assert.Contains(t, auth[0].Value(), `nonce="second"`)
	})

}

func TestDialogClientACKRetransmission(t *testing.T) {
	var acks int32
	client := testClientResponder(t, func(req *sip.Request, w *siptest.ClientTxResponder) {
		if req.IsAck() {
			atomic.AddInt32(&acks, 1)
			return
		}

		res := sip.NewResponseFromRequest(req, 200, "OK", nil)
		w.Receive(res)
		time.Sleep(sip.T1)
		w.Receive(res)
		time.Sleep(sip.T1)
		w.Receive(res)
	})

	dua := DialogUA{
		Client: client,
	}
	d, err := dua.Invite(context.TODO(), sip.Uri{User: "test", Host: "localhost"}, nil)
	require.NoError(t, err)
	err = d.WaitAnswer(context.TODO(), AnswerOptions{})
	require.NoError(t, err)

	// We will keep receiving retransmission
	if err := d.Ack(context.TODO()); err != nil {
		t.Error(err)
	}
	time.Sleep(4 * sip.T1)
	// It should retransmit
	state := d.LoadState()
	assert.Equal(t, sip.DialogStateConfirmed, state)
	assert.EqualValues(t, 3, atomic.LoadInt32(&acks))
}

func BenchmarkDialogDo(b *testing.B) {
	ua, _ := NewUA()
	cli, _ := NewClient(ua)
	cli.TxRequester = &siptest.ClientTxRequester{
		OnRequest: func(req *sip.Request) *sip.Response {
			return sip.NewResponseFromRequest(req, 200, "OK", nil)
		},
	}
	dua := &DialogUA{
		Client: cli,
	}

	dialog, err := dua.Invite(context.TODO(), sip.Uri{User: "test", Host: "localhost"}, nil)
	require.NoError(b, err)
	dialog.WaitAnswer(context.TODO(), AnswerOptions{})

	b.Run("ACK", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			dialog.Ack(context.TODO())
		}
	})
	b.Run("NotSupported", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			req := sip.NewRequest(sip.REFER, sip.Uri{User: "refer", Host: "localhost"})
			dialog.Do(context.TODO(), req)
		}
	})

}
