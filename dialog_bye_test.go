package sipgo

import (
	"bytes"
	"io"
	"log/slog"
	"testing"

	"github.com/emiago/sipgo/fakes"
	"github.com/emiago/sipgo/sip"
	"github.com/emiago/sipgo/siptest"
	"github.com/stretchr/testify/require"
)

func TestDialogServerReadByeCompletion(t *testing.T) {
	for _, name := range []string{"success", "write failure", "invalid CSeq", "unknown dialog"} {
		t.Run(name, func(t *testing.T) {
			invite, _, _ := createTestInvite(t, "sip:uas@127.0.0.1", "TLS", "127.0.0.1:5090")
			invite.AppendHeader(&sip.ContactHeader{Address: sip.Uri{Host: "127.0.0.1", Port: 5090}})
			inviteTx := siptest.NewServerTxRecorder(invite)
			t.Cleanup(inviteTx.Terminate)
			cache := NewDialogServerCache(nil, sip.ContactHeader{})
			dialog, err := cache.ReadInvite(invite, inviteTx)
			require.NoError(t, err)
			t.Cleanup(func() { _ = dialog.Close() })
			dialog.setState(sip.DialogStateConfirmed)
			res := sip.NewResponseFromRequest(dialog.InviteRequest, 200, "OK", nil)
			require.NoError(t, inviteTx.Respond(res))
			bye := newByeRequestUAC(dialog.InviteRequest, res, nil)
			bye.CSeq().SeqNo++
			if name == "invalid CSeq" {
				bye.CSeq().SeqNo = invite.CSeq().SeqNo - 1
			}
			if name == "unknown dialog" {
				bye.To().Params.Add("tag", "unrelated-dialog")
			}

			var response bytes.Buffer
			writer := io.Writer(&response)
			if name == "write failure" {
				r, w := io.Pipe()
				t.Cleanup(func() { _ = r.Close() })
				require.NoError(t, w.Close())
				writer = w
			}
			conn := &sip.TCPConnection{Conn: &fakes.TCPConn{Writer: writer}}
			conn.Ref(1)
			byeTx := sip.NewServerTx("bye", bye, conn, slog.Default())
			require.NoError(t, byeTx.Init())
			t.Cleanup(byeTx.Terminate)

			err = cache.ReadBye(bye, byeTx)
			switch name {
			case "invalid CSeq", "unknown dialog":
				if name == "invalid CSeq" {
					require.ErrorIs(t, err, ErrDialogInvalidCseq)
				} else {
					require.ErrorIs(t, err, ErrDialogDoesNotExists)
				}
				require.Equal(t, sip.DialogStateConfirmed, dialog.LoadState())
				require.NoError(t, dialog.Context().Err())
				require.Same(t, dialog, cache.loadDialog(dialog.ID))
				require.Empty(t, response.String())
				select {
				case <-inviteTx.Done():
					t.Fatal("invalid BYE terminated the INVITE transaction")
				default:
				}
				return
			case "write failure":
				require.ErrorIs(t, err, sip.ErrTransactionTransport)
			default:
				require.NoError(t, err)
				require.Contains(t, response.String(), "SIP/2.0 200 OK")
			}

			// Diago closes media after ReadBye returns, so completion must already be visible.
			require.Equal(t, sip.DialogStateEnded, dialog.LoadState())
			select {
			case <-dialog.Context().Done():
			default:
				t.Fatal("valid BYE left the dialog context live")
			}
			require.Nil(t, cache.loadDialog(dialog.ID))
			select {
			case <-inviteTx.Done():
			default:
				t.Fatal("valid BYE did not terminate the INVITE transaction")
			}
		})
	}
}

func TestDialogClientReadByeResponseFailureCleanup(t *testing.T) {
	invite, _, _ := createTestInvite(t, "sip:uas@127.0.0.1", "TLS", "127.0.0.1:5090")
	inviteConn := &sip.TCPConnection{Conn: &fakes.TCPConn{Writer: io.Discard}}
	inviteConn.Ref(1)
	inviteTx := sip.NewClientTx("invite", invite, inviteConn, slog.Default())
	require.NoError(t, inviteTx.Init())
	t.Cleanup(inviteTx.Terminate)
	closed := false
	dialog := &DialogClientSession{
		Dialog:   Dialog{InviteRequest: invite},
		inviteTx: inviteTx,
		onClose:  func() { closed = true },
	}
	dialog.InitWithState(sip.DialogStateConfirmed)
	bye := newByeRequestUAC(invite, sip.NewResponseFromRequest(invite, 200, "OK", nil), nil)
	r, w := io.Pipe()
	t.Cleanup(func() { _ = r.Close() })
	require.NoError(t, w.Close())
	conn := &sip.TCPConnection{Conn: &fakes.TCPConn{Writer: w}}
	conn.Ref(1)
	byeTx := sip.NewServerTx("bye", bye, conn, slog.Default())
	require.NoError(t, byeTx.Init())
	t.Cleanup(byeTx.Terminate)

	err := dialog.ReadBye(bye, byeTx)
	require.ErrorIs(t, err, sip.ErrTransactionTransport)
	require.Equal(t, sip.DialogStateEnded, dialog.LoadState())
	require.Error(t, dialog.Context().Err())
	require.True(t, closed, "a failed BYE response must still remove the dialog")
	select {
	case <-inviteTx.Done():
	default:
		t.Fatal("failed BYE response left the INVITE transaction alive")
	}
}
