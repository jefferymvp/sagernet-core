package simpleobfs

import (
	"context"
	"github.com/v2fly/v2ray-core/v4/common"
	"github.com/v2fly/v2ray-core/v4/common/net"
	"github.com/v2fly/v2ray-core/v4/proxy"
	"github.com/v2fly/v2ray-core/v4/transport"
	"github.com/v2fly/v2ray-core/v4/transport/internet"
)

func init() {
	common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		c := config.(*ClientConfig)
		return &outbound{
			dest: c.Server.AsDestination(),
			host: c.Host,
			mode: c.Mode,
		}, nil
	})
}

var _ proxy.Outbound = (*outbound)(nil)

type outbound struct {
	dest net.Destination
	host string
	mode string

	processor func(ctx context.Context, link *transport.Link, dialer internet.Dialer) error
}

func (o *outbound) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	if o.processor == nil {
		if o.mode == "http" {
			o.processor = o.processHttp
		} else {
			o.processor = o.processTLS
		}
	}
	return o.processor(ctx, link, dialer)
}
