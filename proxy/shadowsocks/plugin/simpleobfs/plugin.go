package simpleobfs

import (
	"flag"
	"strconv"

	"google.golang.org/protobuf/types/known/anypb"

	core "github.com/v2fly/v2ray-core/v4"
	"github.com/v2fly/v2ray-core/v4/app/dispatcher"
	"github.com/v2fly/v2ray-core/v4/app/proxyman"
	"github.com/v2fly/v2ray-core/v4/common/net"
	"github.com/v2fly/v2ray-core/v4/common/serial"
	"github.com/v2fly/v2ray-core/v4/proxy/dokodemo"
	"github.com/v2fly/v2ray-core/v4/proxy/freedom"
	"github.com/v2fly/v2ray-core/v4/proxy/shadowsocks"
	"github.com/v2fly/v2ray-core/v4/proxy/shadowsocks/plugin/self"
)

//go:generate go run github.com/v2fly/v2ray-core/v4/common/errors/errorgen

var _ shadowsocks.SIP003Plugin = (*Plugin)(nil)

type Plugin struct {
	Server   bool
	instance *core.Instance
}

func (p *Plugin) Init(localHost string, localPort string, remoteHost string, remotePort string, pluginOpts string, pluginArgs []string) error {
	opts := make(self.Args)
	opts.Add("localAddr", localHost)
	opts.Add("l", localPort)
	opts.Add("s", remoteHost)
	opts.Add("p", remotePort)

	if len(pluginOpts) > 0 {
		otherOpts, err := self.ParsePluginOptions(pluginOpts)
		if err != nil {
			return err
		}
		for k, v := range otherOpts {
			opts[k] = v
		}
	}

	config, err := p.init(opts, pluginArgs)
	if err != nil {
		return newError("create config for simple-obfs-plugin").Base(err)
	}

	instance, err := core.New(config)
	if err != nil {
		return newError("create core for simple-obfs-plugin").Base(err)
	}

	err = instance.Start()

	if err != nil {
		return newError("start core for simple-obfs-plugin").Base(err)
	}

	p.instance = instance

	return nil
}

func (p *Plugin) init(opts self.Args, pluginArgs []string) (*core.Config, error) {
	flag := flag.NewFlagSet("simple-obfs-plugin", flag.ContinueOnError)
	var (
		localAddr  = flag.String("localAddr", "127.0.0.1", "local address to listen on.")
		localPort  = flag.String("l", "1984", "local port to listen on.")
		remoteAddr = flag.String("s", "127.0.0.1", "remote server address")
		remotePort = flag.String("p", "1080", "remote port to forward.")
		host       = flag.String("obfs-host", "cloudfront.com", "Hostname for server.")
		mode       = flag.String("obfs", "http", "http or tls")
		fallover   = flag.String("fallover", "", "fallback server")
		logLevel   = flag.String("loglevel", "debug", "loglevel for self: debug, info, warning (default), error, none.")
	)
	flag.Parse(pluginArgs)

	if c, b := opts.Get("mode"); b {
		*mode = c
	}

	if c, b := opts.Get("localAddr"); b {
		if p.Server {
			*remoteAddr = c
		} else {
			*localAddr = c
		}
	}

	if c, b := opts.Get("l"); b {
		if p.Server {
			*remotePort = c
		} else {
			*localPort = c
		}
	}

	if c, b := opts.Get("s"); b {
		if p.Server {
			*localAddr = c
		} else {
			*remoteAddr = c
		}
	}

	if c, b := opts.Get("p"); b {
		if p.Server {
			*localPort = c
		} else {
			*remotePort = c
		}
	}

	if c, b := opts.Get("loglevel"); b {
		*logLevel = c
	}

	if c, b := opts.Get("host"); b {
		*host = c
	}

	if c, b := opts.Get("fallover"); b {
		*fallover = c
	}

	lport, err := net.PortFromString(*localPort)
	if err != nil {
		return nil, newError("invalid localPort:", *localPort).Base(err)
	}

	rport, err := strconv.ParseUint(*remotePort, 10, 32)
	if err != nil {
		return nil, newError("invalid remotePort:", *remotePort).Base(err)
	}

	apps := []*anypb.Any{
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.InboundConfig{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		serial.ToTypedMessage(self.LogConfig(*logLevel)),
	}

	var config *core.Config

	if p.Server {
		localAddrs := self.ParseLocalAddr(*localAddr)
		inbounds := make([]*core.InboundHandlerConfig, len(localAddrs))
		inbound := &ServerConfig{
			Upstream: &net.Endpoint{
				Network: net.Network_TCP,
				Address: net.NewIPOrDomain(net.ParseAddress(*remoteAddr)),
				Port:    uint32(rport),
			},
			Host: *host,
			Mode: *mode,
		}
		if *fallover != "" {
			dest, err := net.ParseDestination(*fallover)
			if err != nil {
				return nil, newError("failed to parse fallover destination: ", *fallover).Base(err)
			}
			inbound.Fallover = &net.Endpoint{
				Network: net.Network_TCP,
				Address: net.NewIPOrDomain(dest.Address),
				Port:    uint32(dest.Port),
			}
		}
		for i := 0; i < len(localAddrs); i++ {
			inbounds[i] = &core.InboundHandlerConfig{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortRange: net.SinglePortRange(lport),
					Listen:    net.NewIPOrDomain(net.ParseAddress(localAddrs[i])),
				}),
				ProxySettings: serial.ToTypedMessage(inbound),
			}
		}
		config = &core.Config{
			Inbound: inbounds,
			Outbound: []*core.OutboundHandlerConfig{{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{}),
			}},
			App: apps,
		}
	} else {
		outbound := &ClientConfig{
			Server: &net.Endpoint{
				Network: net.Network_TCP,
				Address: net.NewIPOrDomain(net.ParseAddress(*remoteAddr)),
				Port:    uint32(rport),
			},
			Host: *host,
			Mode: *mode,
		}
		config = &core.Config{
			Inbound: []*core.InboundHandlerConfig{{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortRange: net.SinglePortRange(lport),
					Listen:    net.NewIPOrDomain(net.ParseAddress(*localAddr)),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address:  net.NewIPOrDomain(net.LocalHostIP),
					Networks: []net.Network{net.Network_TCP},
				}),
			}},
			Outbound: []*core.OutboundHandlerConfig{
				{
					ProxySettings: serial.ToTypedMessage(outbound),
				},
			},
			App: apps,
		}
	}

	return config, nil

}

func (p *Plugin) Close() error {
	if p.instance == nil {
		return nil
	}
	return p.instance.Close()
}
