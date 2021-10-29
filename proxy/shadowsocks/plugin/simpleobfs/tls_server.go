package simpleobfs

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"github.com/v2fly/v2ray-core/v4/common"
	"github.com/v2fly/v2ray-core/v4/common/buf"
	"github.com/v2fly/v2ray-core/v4/common/net"
	"github.com/v2fly/v2ray-core/v4/common/session"
	"github.com/v2fly/v2ray-core/v4/common/tlsdissector"
	"github.com/v2fly/v2ray-core/v4/features/routing"
	"github.com/v2fly/v2ray-core/v4/transport/internet"
	"time"
)

func (h *inbound) processTLS(ctx context.Context, network net.Network, connection internet.Connection, dispatcher routing.Dispatcher) error {
	cachedReader := &cachedReader{Reader: connection}
	writer := buf.NewBufferedWriter(buf.NewWriter(connection))
	record := &dissector.Record{}

	if _, err := record.ReadFrom(cachedReader); err != nil {
		newError("failed to read tls obfs request").Base(err).WriteToLog(session.ExportIDToError(ctx))
		return h.doFallback(ctx, connection, dispatcher, cachedReader.cachedBytes())
	}

	if record.Type != dissector.Handshake {
		newError("failed to do obfs handshake").Base(dissector.ErrBadType).WriteToLog(session.ExportIDToError(ctx))
		return h.doFallback(ctx, connection, dispatcher, cachedReader.cachedBytes())
	}

	clientMsg := &dissector.ClientHelloMsg{}
	if err := clientMsg.Decode(record.Opaque); err != nil {
		newError("failed to decode client hello message").Base(err).WriteToLog(session.ExportIDToError(ctx))
		return h.doFallback(ctx, connection, dispatcher, cachedReader.cachedBytes())
	}

	link, err := dispatcher.Dispatch(ctx, h.upstream)
	if err != nil {
		newError("failed to connect to upstream").Base(err).WriteToLog(session.ExportIDToError(ctx))
		return h.doFallback(ctx, connection, dispatcher, nil)
	}

	for _, ext := range clientMsg.Extensions {
		if ext.Type() == dissector.ExtSessionTicket {
			payload, err := ext.Encode()
			if err != nil {
				newError("failed to decode payload").Base(err).WriteToLog(session.ExportIDToError(ctx))
				return h.doFallback(ctx, connection, dispatcher, cachedReader.cachedBytes())
			}
			if err = link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.As(payload)}); err != nil {
				newError("failed to send payload to upstream").Base(err).WriteToLog(session.ExportIDToError(ctx))
				return h.doFallback(ctx, connection, dispatcher, cachedReader.cachedBytes())
			}
			break
		}
	}

	cachedReader.release()

	serverMsg := &dissector.ServerHelloMsg{
		Version:           tls.VersionTLS12,
		SessionID:         clientMsg.SessionID,
		CipherSuite:       0xcca8,
		CompressionMethod: 0x00,
		Extensions: []dissector.Extension{
			&dissector.RenegotiationInfoExtension{},
			&dissector.ExtendedMasterSecretExtension{},
			&dissector.ECPointFormatsExtension{
				Formats: []uint8{0x00},
			},
		},
	}

	serverMsg.Random.Time = uint32(time.Now().Unix())
	rand.Read(serverMsg.Random.Opaque[:])
	b, err := serverMsg.Encode()
	if err != nil {
		return err
	}

	record = &dissector.Record{
		Type:    dissector.Handshake,
		Version: tls.VersionTLS10,
		Opaque:  b,
	}
	common.Must2(record.WriteTo(writer))
	record = &dissector.Record{
		Type:    dissector.ChangeCipherSpec,
		Version: tls.VersionTLS12,
		Opaque:  []byte{0x01},
	}
	common.Must2(record.WriteTo(writer))

	return nil
}

var _ net.Conn = (*tlsObfsServerConn)(nil)

type tlsObfsServerConn struct {
	net.Conn
}

func (c tlsObfsServerConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	record := &dissector.Record{}
	_, err := record.ReadFrom(c.Conn)
	if err != nil {
		return nil, err
	}
	return buf.AsMulti(record.Opaque), nil
}

func (c tlsObfsServerConn) WriteMultiBuffer(buffer buf.MultiBuffer) error {
	defer buf.ReleaseMulti(buffer)
	for !buffer.IsEmpty() {
		var data buf.MultiBuffer
		buffer, data = buf.SplitSize(buffer, maxTLSDataLen)
		record := &dissector.Record{
			Type:    dissector.AppData,
			Version: tls.VersionTLS12,
			Opaque:  data.Bytes(),
		}
		_, err := record.WriteTo(c.Conn)
		if err != nil {
			return err
		}
	}
	return nil
}
