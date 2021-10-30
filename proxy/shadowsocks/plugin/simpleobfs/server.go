package simpleobfs

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/v2fly/v2ray-core/v4/common"
	"github.com/v2fly/v2ray-core/v4/common/buf"
	"github.com/v2fly/v2ray-core/v4/common/net"
	"github.com/v2fly/v2ray-core/v4/common/session"
	"github.com/v2fly/v2ray-core/v4/common/task"
	"github.com/v2fly/v2ray-core/v4/features/routing"
	"github.com/v2fly/v2ray-core/v4/proxy"
	"github.com/v2fly/v2ray-core/v4/transport/internet"
)

func init() {
	common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		c := config.(*ServerConfig)
		i := &inbound{
			upstream: c.Upstream.AsDestination(),
			host:     c.Host,
			mode:     c.Mode,
		}
		switch c.Mode {
		case "http":
			i.processor = i.processHTTP
		case "tls":
			i.processor = i.processTLS
		default:
			return nil, newError("unknown obfs mode ", c.Mode)
		}

		if c.Fallover != nil {
			i.fallback = c.Fallover.AsDestination()
		}
		return i, nil
	})
}

var _ proxy.Inbound = (*inbound)(nil)

type inbound struct {
	upstream net.Destination
	host     string
	mode     string
	fallback net.Destination

	processor func(ctx context.Context, network net.Network, connection internet.Connection, dispatcher routing.Dispatcher) error
}

func (h *inbound) Process(ctx context.Context, network net.Network, connection internet.Connection, dispatcher routing.Dispatcher) error {
	return h.processor(ctx, network, connection, dispatcher)
}

func (h *inbound) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (h *inbound) doFallback(ctx context.Context, connection internet.Connection, dispatcher routing.Dispatcher, payload buf.MultiBuffer) error {
	if !h.fallback.IsValid() {
		common.Close(connection)
		return nil
	}

	link, err := dispatcher.Dispatch(ctx, h.fallback)
	if err != nil {
		return newError("failed to read fallback").Base(err)
	}
	if payload != nil && !payload.IsEmpty() {
		if err = link.Writer.WriteMultiBuffer(payload); err != nil {
			return newError("failed to write payload to fallback").Base(err)
		}
	}
	if err = task.Run(ctx, func() error {
		return buf.Copy(buf.NewReader(connection), link.Writer)
	}, func() error {
		return buf.Copy(link.Reader, buf.NewWriter(connection))
	}); err != nil {
		return newError("fallback connection ends").Base(err)
	}
	return nil
}

func (h *inbound) processHTTP(ctx context.Context, _ net.Network, connection internet.Connection, dispatcher routing.Dispatcher) error {
	cachedReader := &cachedReader{Reader: connection}
	br := bufio.NewReader(cachedReader)
	request, err := http.ReadRequest(br)
	if err != nil {
		newError("failed to read http obfs request").Base(err).WriteToLog(session.ExportIDToError(ctx))
		return h.doFallback(ctx, connection, dispatcher, cachedReader.cachedBytes())
	}
	link, err := dispatcher.Dispatch(ctx, h.upstream)
	if err != nil {
		newError("failed to connect to upstream").Base(err).WriteToLog(session.ExportIDToError(ctx))
		return h.doFallback(ctx, connection, dispatcher, nil)
	}
	if request.ContentLength > 0 {
		if err := buf.Copy(buf.NewReader(request.Body), link.Writer); err != nil {
			newError("failed to send payload to upstream").Base(err).WriteToLog(session.ExportIDToError(ctx))
			return h.doFallback(ctx, connection, dispatcher, cachedReader.cachedBytes())
		}
	}
	websocketKey := request.Header.Get("Sec-WebSocket-Key")
	if request.Method != http.MethodGet || request.Header.Get("Upgrade") != "websocket" || websocketKey == "" {
		return h.doFallback(ctx, connection, dispatcher, cachedReader.cachedBytes())
	}
	cachedReader.release()

	acceptHash := sha1.New()
	acceptHash.Write([]byte(websocketKey))
	acceptHash.Write([]byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	acceptKey := base64.StdEncoding.EncodeToString(acceptHash.Sum(nil))

	response := http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Server":               []string{"nginx/1.18.0"},
			"Date":                 []string{time.Now().Format(time.RFC1123)},
			"Connection":           []string{"Upgrade"},
			"Upgrade":              []string{"websocket"},
			"Sec-WebSocket-Accept": []string{acceptKey},
		},
	}

	if err := task.OnSuccess(func() error {
		return response.Write(connection)
	}, func() error {
		return task.Run(ctx, func() error {
			return buf.Copy(link.Reader, buf.NewWriter(connection))
		}, func() error {
			return buf.Copy(buf.NewReader(br), link.Writer)
		})
	}); err != nil {
		return newError("connection ends").Base(err())
	}

	return nil

}

func (h *inbound) processTLS(ctx context.Context, network net.Network, connection internet.Connection, dispatcher routing.Dispatcher) error {
	conn := ServerObfsTLSConn(connection)
	link, err := dispatcher.Dispatch(ctx, h.upstream)
	if err != nil {
		newError("failed to connect to upstream").Base(err).WriteToLog(session.ExportIDToError(ctx))
		return h.doFallback(ctx, connection, dispatcher, nil)
	}
	if err := task.Run(ctx, func() error {
		return buf.Copy(buf.NewReader(conn), link.Writer)
	}, func() error {
		return buf.Copy(link.Reader, buf.NewWriter(conn))
	}); err != nil {
		return newError("connection ends").Base(err)
	}
	return nil
}
