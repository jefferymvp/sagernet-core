package simpleobfs

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	gonet "net"
	"net/http"
	"time"

	"github.com/v2fly/v2ray-core/v4/common"
	"github.com/v2fly/v2ray-core/v4/common/buf"
	"github.com/v2fly/v2ray-core/v4/common/net"
	"github.com/v2fly/v2ray-core/v4/common/task"
	"github.com/v2fly/v2ray-core/v4/proxy"
	"github.com/v2fly/v2ray-core/v4/transport"
	"github.com/v2fly/v2ray-core/v4/transport/internet"
)

func init() {
	common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		c := config.(*ClientConfig)
		o := &outbound{
			dest: c.Server.AsDestination(),
			host: c.Host,
			mode: c.Mode,
		}
		switch c.Mode {
		case "http":
			o.processor = o.processHTTP
		case "tls":
			o.processor = o.processTLS
		default:
			return nil, newError("unknown obfs mode ", c.Mode)
		}

		return o, nil
	})
}

var _ proxy.Outbound = (*outbound)(nil)

type outbound struct {
	dest      net.Destination
	host      string
	mode      string
	processor func(ctx context.Context, link *transport.Link, dialer internet.Dialer) error
}

func (o *outbound) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	return o.processor(ctx, link, dialer)
}

func (o *outbound) processHTTP(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	conn, err := dialer.Dial(ctx, o.dest)
	if err != nil {
		return newError("failed to dial to destination ", o.dest).Base(err)
	}

	bufferedWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/", o.host), nil)
	req.Header.Set("User-Agent", fmt.Sprintf("curl/7.%d.%d", rand.Int()%54, rand.Int()%2))
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Host = o.host
	if o.dest.Port != 80 {
		req.Host = gonet.JoinHostPort(o.host, o.dest.Port.String())
	}
	req.Header.Set("Sec-WebSocket-Key", base64.URLEncoding.EncodeToString(randBytes))
	req.Write(bufferedWriter)
	if err = buf.CopyOnceTimeout(link.Reader, bufferedWriter, time.Millisecond*100); err != nil && err != buf.ErrNotTimeoutReader && err != buf.ErrReadTimeout {
		return newError("failed to write A request payload").Base(err).AtWarning()
	}

	bufferedWriter.SetBuffered(false)
	if err = task.Run(ctx, func() error {
		return buf.Copy(link.Reader, bufferedWriter)
	}, func() error {
		br := bufio.NewReader(conn)
		response, err := http.ReadResponse(br, req)
		if err != nil {
			return newError("failed to parse response").Base(err)
		}
		if response.StatusCode != http.StatusSwitchingProtocols || response.Header.Get("Upgrade") != "websocket" {
			return newError("unexpected response: ", response.Status)
		}
		if response.ContentLength > 0 {
			if err = buf.Copy(buf.NewReader(response.Body), link.Writer); err != nil {
				return newError("failed to write payload").Base(err)
			}
		}
		return buf.Copy(buf.NewReader(br), link.Writer)
	}); err != nil {
		return newError("connection ends").Base(err)
	}

	return nil

}

func (o *outbound) processTLS(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	conn, err := dialer.Dial(ctx, o.dest)
	if err != nil {
		return newError("failed to dial to destination ", o.dest).Base(err)
	}
	conn = ClientObfsTLSConn(conn, o.host)
	if err := task.Run(ctx, func() error {
		return buf.Copy(link.Reader, buf.NewWriter(conn))
	}, func() error {
		return buf.Copy(buf.NewReader(conn), link.Writer)
	}); err != nil {
		return newError("connection ends").Base(err)
	}
	return nil
}
