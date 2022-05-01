package socks

import (
	"context"
	"time"

	"github.com/sagernet/sing/common/rw"
	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/net/packetaddr"
	"github.com/v2fly/v2ray-core/v5/common/net/udpovertcp"
	"github.com/v2fly/v2ray-core/v5/common/protocol"
	"github.com/v2fly/v2ray-core/v5/common/retry"
	"github.com/v2fly/v2ray-core/v5/common/session"
	"github.com/v2fly/v2ray-core/v5/common/signal"
	"github.com/v2fly/v2ray-core/v5/common/task"
	"github.com/v2fly/v2ray-core/v5/features/dns"
	"github.com/v2fly/v2ray-core/v5/features/policy"
	"github.com/v2fly/v2ray-core/v5/transport"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"github.com/v2fly/v2ray-core/v5/transport/internet/udp"
)

// Client is a Socks5 client.
type Client struct {
	serverPicker  protocol.ServerPicker
	policyManager policy.Manager
	version       Version
	dns           dns.Client
	uot           bool
}

// NewClient create a new Socks5 client based on the given config.
func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	serverList := protocol.NewServerList()
	for _, rec := range config.Server {
		s, err := protocol.NewServerSpecFromPB(rec)
		if err != nil {
			return nil, newError("failed to get server spec").Base(err)
		}
		serverList.AddServer(s)
	}
	if serverList.Size() == 0 {
		return nil, newError("0 target server")
	}

	v := core.MustFromContext(ctx)
	c := &Client{
		serverPicker:  protocol.NewRoundRobinServerPicker(serverList),
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		version:       config.Version,
	}
	if config.Version == Version_SOCKS4 {
		c.dns = v.GetFeature(dns.ClientType()).(dns.Client)
	}
	c.uot = config.UdpOverTcp

	return c, nil
}

func (c *Client) ProcessConn(ctx context.Context, conn net.Conn, dialer internet.Dialer) error {
	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("target not specified.")
	}
	// Destination of the inner request.
	destination := outbound.Target

	// Outbound server.
	var server *protocol.ServerSpec
	// Outbound server's destination.
	var dest net.Destination
	// Connection to the outbound server.
	var outboundConn internet.Connection

	if err := retry.ExponentialBackoff(5, 100).On(func() error {
		server = c.serverPicker.PickServer()
		dest = server.Destination()
		rawConn, err := dialer.Dial(ctx, dest)
		if err != nil {
			return err
		}
		outboundConn = rawConn

		return nil
	}); err != nil {
		return newError("failed to find an available destination").Base(err)
	}

	connElem := net.AddConnection(outboundConn)
	defer net.RemoveConnection(connElem)

	request := &protocol.RequestHeader{
		Version: socks5Version,
		Command: protocol.RequestCommandTCP,
		Address: destination.Address,
		Port:    destination.Port,
	}

	switch c.version {
	case Version_SOCKS4:
		if request.Address.Family().IsDomain() {
			lookupFunc := c.dns.LookupIP
			if lookupIPv4, ok := c.dns.(dns.IPv4Lookup); ok {
				lookupFunc = lookupIPv4.LookupIPv4
			}
			ips, err := lookupFunc(request.Address.Domain())
			if err != nil {
				return err
			} else if len(ips) == 0 {
				return dns.ErrEmptyResponse
			}
			request.Address = net.IPAddress(ips[0])
		}
		fallthrough
	case Version_SOCKS4A:
		request.Version = socks4Version

		if destination.Network == net.Network_UDP && !c.uot {
			return newError("udp is not supported in socks4")
		} else if destination.Address.Family().IsIPv6() {
			return newError("ipv6 is not supported in socks4")
		}
	}

	if destination.Network == net.Network_UDP {
		if !c.uot {
			request.Command = protocol.RequestCommandUDP
		} else {
			request.Address = net.DomainAddress(udpovertcp.UOTMagicAddress)
			request.Port = 443
		}
	}

	p := c.policyManager.ForLevel(0)
	user := server.PickUser()
	if user != nil {
		request.User = user
		p = c.policyManager.ForLevel(user.Level)
	}

	if err := outboundConn.SetDeadline(time.Now().Add(p.Timeouts.Handshake)); err != nil {
		newError("failed to set deadline for handshake").Base(err).WriteToLog(session.ExportIDToError(ctx))
	}
	udpRequest, err := ClientHandshake(request, outboundConn, outboundConn)
	if err != nil {
		return newError("failed to establish connection to server").AtWarning().Base(err)
	}
	if udpRequest != nil {
		if udpRequest.Address == net.AnyIP || udpRequest.Address == net.AnyIPv6 {
			udpRequest.Address = dest.Address
		}
	}

	if err := outboundConn.SetDeadline(time.Time{}); err != nil {
		newError("failed to clear deadline after handshake").Base(err).WriteToLog(session.ExportIDToError(ctx))
	}

	return rw.CopyConn(ctx, conn, outboundConn)
}

// Process implements proxy.Outbound.Process.
func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("target not specified.")
	}
	// Destination of the inner request.
	destination := outbound.Target

	// Outbound server.
	var server *protocol.ServerSpec
	// Outbound server's destination.
	var dest net.Destination
	// Connection to the outbound server.
	var conn internet.Connection

	if err := retry.ExponentialBackoff(5, 100).On(func() error {
		server = c.serverPicker.PickServer()
		dest = server.Destination()
		rawConn, err := dialer.Dial(ctx, dest)
		if err != nil {
			return err
		}
		conn = rawConn

		return nil
	}); err != nil {
		return newError("failed to find an available destination").Base(err)
	}

	connElem := net.AddConnection(conn)
	defer net.RemoveConnection(connElem)

	p := c.policyManager.ForLevel(0)

	request := &protocol.RequestHeader{
		Version: socks5Version,
		Command: protocol.RequestCommandTCP,
		Address: destination.Address,
		Port:    destination.Port,
	}

	switch c.version {
	case Version_SOCKS4:
		if request.Address.Family().IsDomain() {
			lookupFunc := c.dns.LookupIP
			if lookupIPv4, ok := c.dns.(dns.IPv4Lookup); ok {
				lookupFunc = lookupIPv4.LookupIPv4
			}
			ips, err := lookupFunc(request.Address.Domain())
			if err != nil {
				return err
			} else if len(ips) == 0 {
				return dns.ErrEmptyResponse
			}
			request.Address = net.IPAddress(ips[0])
		}
		fallthrough
	case Version_SOCKS4A:
		request.Version = socks4Version

		if destination.Network == net.Network_UDP && !c.uot {
			return newError("udp is not supported in socks4")
		} else if destination.Address.Family().IsIPv6() {
			return newError("ipv6 is not supported in socks4")
		}
	}

	if destination.Network == net.Network_UDP {
		if !c.uot {
			request.Command = protocol.RequestCommandUDP
		} else {
			request.Address = net.DomainAddress(udpovertcp.UOTMagicAddress)
			request.Port = 443
		}
	}

	user := server.PickUser()
	if user != nil {
		request.User = user
		p = c.policyManager.ForLevel(user.Level)
	}

	if err := conn.SetDeadline(time.Now().Add(p.Timeouts.Handshake)); err != nil {
		newError("failed to set deadline for handshake").Base(err).WriteToLog(session.ExportIDToError(ctx))
	}
	udpRequest, err := ClientHandshake(request, conn, conn)
	if err != nil {
		return newError("failed to establish connection to server").AtWarning().Base(err)
	}
	if udpRequest != nil {
		if udpRequest.Address == net.AnyIP || udpRequest.Address == net.AnyIPv6 {
			udpRequest.Address = dest.Address
		}
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		newError("failed to clear deadline after handshake").Base(err).WriteToLog(session.ExportIDToError(ctx))
	}

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, p.Timeouts.ConnectionIdle)

	if packetConn, err := packetaddr.ToPacketAddrConn(link, destination); err == nil {
		udpConn, err := dialer.Dial(ctx, udpRequest.Destination())
		if err != nil {
			return newError("failed to create UDP connection").Base(err)
		}
		defer udpConn.Close()

		requestDone := func() error {
			protocolWriter := NewUDPWriter(request, udpConn)
			return udp.CopyPacketConn(protocolWriter, packetConn, udp.UpdateActivity(timer))
		}
		responseDone := func() error {
			protocolReader := &UDPReader{
				reader: udpConn,
			}
			return udp.CopyPacketConn(packetConn, protocolReader, udp.UpdateActivity(timer))
		}
		responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
		if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
			return newError("connection ends").Base(err)
		}
		return nil
	}

	var requestFunc func() error
	var responseFunc func() error
	if destination.Network == net.Network_UDP && c.uot {
		requestFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
			writer := udpovertcp.NewWriter(conn, &destination)
			return buf.Copy(link.Reader, writer, buf.UpdateActivity(timer))
		}
		responseFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.UplinkOnly)
			reader := udpovertcp.NewReader(conn)
			return buf.Copy(reader, link.Writer, buf.UpdateActivity(timer))
		}
	} else if request.Command == protocol.RequestCommandTCP {
		requestFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
			return buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer))
		}
		responseFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.UplinkOnly)
			return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
		}
	} else if request.Command == protocol.RequestCommandUDP {
		udpConn, err := dialer.Dial(ctx, udpRequest.Destination())
		if err != nil {
			return newError("failed to create UDP connection").Base(err)
		}
		defer udpConn.Close()
		requestFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
			return buf.Copy(link.Reader, NewUDPWriter(request, udpConn), buf.UpdateActivity(timer))
		}
		responseFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.UplinkOnly)
			reader := &UDPReader{reader: udpConn}
			return buf.Copy(reader, link.Writer, buf.UpdateActivity(timer))
		}
	}

	responseDonePost := task.OnSuccess(responseFunc, task.Close(link.Writer))
	if err := task.Run(ctx, requestFunc, responseDonePost); err != nil {
		return newError("connection ends").Base(err)
	}

	return nil
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}
