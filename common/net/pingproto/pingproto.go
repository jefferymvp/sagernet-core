package pingproto

import (
	"os"
	"strings"
	"syscall"

	"golang.org/x/net/icmp"

	"github.com/v2fly/v2ray-core/v5/common/net"
)

//go:generate go run github.com/v2fly/v2ray-core/v5/common/errors/errorgen

var ControlFunc func(fd uintptr)

func ListenPacket(network, address string) (conn net.PacketConn, err error) {
	if strings.HasPrefix(network, "udp") && ControlFunc != nil {
		var family, proto int
		switch network {
		case "udp4":
			family, proto = syscall.AF_INET, syscall.IPPROTO_ICMP
		case "udp6":
			family, proto = syscall.AF_INET6, syscall.IPPROTO_ICMPV6
		}
		fd, err := syscall.Socket(family, syscall.SOCK_DGRAM, proto)
		if err != nil {
			return nil, os.NewSyscallError("socket", err)
		}
		ControlFunc(uintptr(fd))
		file := os.NewFile(uintptr(fd), "datagram-oriented icmp")
		defer file.Close()
		conn, err = net.FilePacketConn(file)
		return conn, err
	}
	conn, err = icmp.ListenPacket(network, address)
	if ControlFunc != nil {
		rawConn, err := conn.(syscall.Conn).SyscallConn()
		if err != nil {
			newError("failed to get raw conn for icmp conn").Base(err).WriteToLog()
		} else {
			err = rawConn.Control(ControlFunc)
			if err != nil {
				newError("failed to control icmp conn").Base(err).WriteToLog()
			}
		}
	}
	return
}
