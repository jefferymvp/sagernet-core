//go:build !confonly
// +build !confonly

package dns

import (
	"context"
	"strings"

	"github.com/v2fly/v2ray-core/v4/common/net"
	"github.com/v2fly/v2ray-core/v4/common/task"
	"github.com/v2fly/v2ray-core/v4/features/dns"
	"github.com/v2fly/v2ray-core/v4/features/dns/localdns"
)

// LocalNameServer is an wrapper over local DNS feature.
type LocalNameServer struct {
	client *localdns.Client
}

const errEmptyResponse = "No address associated with hostname"

// QueryIP implements Server.
func (s *LocalNameServer) QueryIP(ctx context.Context, domain string, _ net.IP, option dns.IPOption, _ bool) ([]net.IP, error) {
	var ips []net.IP
	var err error

	_ = task.Run(ctx, func() error {
		switch {
		case option.IPv4Enable && option.IPv6Enable:
			ips, err = s.client.LookupIP(domain)
		case option.IPv4Enable:
			ips, err = s.client.LookupIPv4(domain)
		case option.IPv6Enable:
			ips, err = s.client.LookupIPv6(domain)
		}
		return nil
	})

	if err != nil && strings.HasSuffix(err.Error(), errEmptyResponse) {
		err = dns.ErrEmptyResponse
	}

	if len(ips) > 0 {
		newError("Localhost got answer: ", domain, " -> ", ips).AtInfo().WriteToLog()
	}

	return ips, err
}

// Name implements Server.
func (s *LocalNameServer) Name() string {
	return "localhost"
}

// NewLocalNameServer creates localdns server object for directly lookup in system DNS.
func NewLocalNameServer() *LocalNameServer {
	newError("DNS: created localhost client").AtInfo().WriteToLog()
	return &LocalNameServer{
		client: localdns.New(),
	}
}

// NewLocalDNSClient creates localdns client object for directly lookup in system DNS.
func NewLocalDNSClient() *Client {
	return &Client{server: NewLocalNameServer()}
}
