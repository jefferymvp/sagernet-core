//go:build !confonly
// +build !confonly

package encoding

import (
	"context"
	"github.com/v2fly/v2ray-core/v4/transport/internet"
	"google.golang.org/grpc/metadata"

	"google.golang.org/grpc"
)

type ConnHandler interface {
	HandleConn(internet.Connection)
}

func ServerDesc(name string) grpc.ServiceDesc {
	return grpc.ServiceDesc{
		ServiceName: name,
		HandlerType: (*GunServiceServer)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams: []grpc.StreamDesc{
			{
				StreamName: "Tun",
				Handler: func(srv interface{}, stream grpc.ServerStream) error {
					if header, ok := metadata.FromIncomingContext(stream.Context()); ok {
						for key, values := range header {
							if key == "mode" && len(values) == 1 && values[0] == "raw" {
								if err := grpc.SetHeader(stream.Context(), metadata.New(map[string]string{"mode": "raw"})); err != nil {
									return err
								}
								srv.(ConnHandler).HandleConn(NewRawConn(stream))
								return nil
							}
						}
					}

					return _GunService_Tun_Handler(srv, stream)
				},
				ServerStreams: true,
				ClientStreams: true,
			},
		},
		Metadata: "gun.proto",
	}
}

func (c *gunServiceClient) TunCustomName(ctx context.Context, name string, opts ...grpc.CallOption) (GunService_TunClient, error) {
	stream, err := c.cc.NewStream(ctx, &ServerDesc(name).Streams[0], "/"+name+"/Tun", opts...)
	if err != nil {
		return nil, err
	}
	x := &gunServiceTunClient{stream}
	return x, nil
}

type GunServiceClientX interface {
	TunCustomName(ctx context.Context, name string, opts ...grpc.CallOption) (GunService_TunClient, error)
	Tun(ctx context.Context, opts ...grpc.CallOption) (GunService_TunClient, error)
}

func RegisterGunServiceServerX(s *grpc.Server, srv GunServiceServer, name string) {
	desc := ServerDesc(name)
	s.RegisterService(&desc, srv)
}
