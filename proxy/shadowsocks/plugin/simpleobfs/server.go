package simpleobfs

import (
	"context"
	"github.com/v2fly/v2ray-core/v4/common"
	"github.com/v2fly/v2ray-core/v4/common/buf"
	"github.com/v2fly/v2ray-core/v4/common/net"
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
	if h.processor == nil {
		if h.mode == "http" {
			h.processor = h.processHTTP
		} else {
			h.processor = h.processTLS
		}
	}
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
