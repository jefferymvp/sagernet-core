package simpleobfs

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"github.com/v2fly/v2ray-core/v4/common/buf"
	"github.com/v2fly/v2ray-core/v4/common/net"
	"github.com/v2fly/v2ray-core/v4/common/session"
	"github.com/v2fly/v2ray-core/v4/common/task"
	"github.com/v2fly/v2ray-core/v4/features/routing"
	"github.com/v2fly/v2ray-core/v4/transport/internet"
	"net/http"
	"time"
)

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
