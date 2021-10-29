package simpleobfs

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"github.com/v2fly/v2ray-core/v4/common/buf"
	"github.com/v2fly/v2ray-core/v4/common/net"
	"github.com/v2fly/v2ray-core/v4/common/task"
	"github.com/v2fly/v2ray-core/v4/common/tlsdissector"
	"github.com/v2fly/v2ray-core/v4/transport"
	"github.com/v2fly/v2ray-core/v4/transport/internet"
	"time"
)

func (o *outbound) processTLS(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	payload, readPayloadErr := link.Reader.(buf.TimeoutReader).ReadMultiBufferTimeout(time.Millisecond * 100)

	conn, err := dialer.Dial(ctx, o.dest)
	if err != nil {
		return newError("failed to dial to destination ", o.dest).Base(err)
	}

	clientMsg := &dissector.ClientHelloMsg{
		Version:            tls.VersionTLS12,
		SessionID:          make([]byte, 32),
		CipherSuites:       cipherSuites,
		CompressionMethods: compressionMethods,
		Extensions: []dissector.Extension{
			&dissector.ServerNameExtension{
				Name: o.host,
			},
			&dissector.ECPointFormatsExtension{
				Formats: []uint8{0x01, 0x00, 0x02},
			},
			&dissector.SupportedGroupsExtension{
				Groups: []uint16{0x001d, 0x0017, 0x0019, 0x0018},
			},
			&dissector.SignatureAlgorithmsExtension{
				Algorithms: algorithms,
			},
			&dissector.EncryptThenMacExtension{},
			&dissector.ExtendedMasterSecretExtension{},
		},
	}
	if readPayloadErr == nil {
		clientMsg.Extensions = append([]dissector.Extension{
			&dissector.SessionTicketExtension{
				Data: payload.Bytes(),
			},
		}, clientMsg.Extensions...)
	}

	clientMsg.Random.Time = uint32(time.Now().Unix())
	rand.Read(clientMsg.Random.Opaque[:])
	rand.Read(clientMsg.SessionID)
	b, err := clientMsg.Encode()
	if err != nil {
		return err
	}

	record := &dissector.Record{
		Type:    dissector.Handshake,
		Version: tls.VersionTLS10,
		Opaque:  b,
	}
	if _, err := record.WriteTo(conn); err != nil {
		return newError("failed to write tls obfs header")
	}

	client := &tlsObfsClientConn{Conn: conn}
	reader := buf.NewReader(client)

	if err = task.Run(ctx, func() error {
		return buf.Copy(link.Reader, client)
	}, func() error {
		return buf.Copy(reader, link.Writer)
	}); err != nil {
		return newError("connection ends").Base(err)
	}

	return nil
}

var _ net.Conn = (*tlsObfsClientConn)(nil)

type tlsObfsClientConn struct {
	net.Conn
	parser *obfsTLSParser
}

func (c *tlsObfsClientConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if err != nil {
		return
	}
	if n > 0 {
		n, err = c.parser.Parse(b[:n])
	}
	return
}

func (c *tlsObfsClientConn) WriteMultiBuffer(buffer buf.MultiBuffer) error {
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
