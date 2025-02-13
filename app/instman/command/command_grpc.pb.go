// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.19.4
// source: app/instman/command/command.proto

package command

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// InstanceManagementServiceClient is the client API for InstanceManagementService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type InstanceManagementServiceClient interface {
	ListInstance(ctx context.Context, in *ListInstanceReq, opts ...grpc.CallOption) (*ListInstanceResp, error)
	AddInstance(ctx context.Context, in *AddInstanceReq, opts ...grpc.CallOption) (*AddInstanceResp, error)
	StartInstance(ctx context.Context, in *StartInstanceReq, opts ...grpc.CallOption) (*StartInstanceResp, error)
}

type instanceManagementServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewInstanceManagementServiceClient(cc grpc.ClientConnInterface) InstanceManagementServiceClient {
	return &instanceManagementServiceClient{cc}
}

func (c *instanceManagementServiceClient) ListInstance(ctx context.Context, in *ListInstanceReq, opts ...grpc.CallOption) (*ListInstanceResp, error) {
	out := new(ListInstanceResp)
	err := c.cc.Invoke(ctx, "/v2ray.core.app.instman.command.InstanceManagementService/ListInstance", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *instanceManagementServiceClient) AddInstance(ctx context.Context, in *AddInstanceReq, opts ...grpc.CallOption) (*AddInstanceResp, error) {
	out := new(AddInstanceResp)
	err := c.cc.Invoke(ctx, "/v2ray.core.app.instman.command.InstanceManagementService/AddInstance", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *instanceManagementServiceClient) StartInstance(ctx context.Context, in *StartInstanceReq, opts ...grpc.CallOption) (*StartInstanceResp, error) {
	out := new(StartInstanceResp)
	err := c.cc.Invoke(ctx, "/v2ray.core.app.instman.command.InstanceManagementService/StartInstance", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// InstanceManagementServiceServer is the server API for InstanceManagementService service.
// All implementations must embed UnimplementedInstanceManagementServiceServer
// for forward compatibility
type InstanceManagementServiceServer interface {
	ListInstance(context.Context, *ListInstanceReq) (*ListInstanceResp, error)
	AddInstance(context.Context, *AddInstanceReq) (*AddInstanceResp, error)
	StartInstance(context.Context, *StartInstanceReq) (*StartInstanceResp, error)
	mustEmbedUnimplementedInstanceManagementServiceServer()
}

// UnimplementedInstanceManagementServiceServer must be embedded to have forward compatible implementations.
type UnimplementedInstanceManagementServiceServer struct {
}

func (UnimplementedInstanceManagementServiceServer) ListInstance(context.Context, *ListInstanceReq) (*ListInstanceResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListInstance not implemented")
}
func (UnimplementedInstanceManagementServiceServer) AddInstance(context.Context, *AddInstanceReq) (*AddInstanceResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddInstance not implemented")
}
func (UnimplementedInstanceManagementServiceServer) StartInstance(context.Context, *StartInstanceReq) (*StartInstanceResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method StartInstance not implemented")
}
func (UnimplementedInstanceManagementServiceServer) mustEmbedUnimplementedInstanceManagementServiceServer() {
}

// UnsafeInstanceManagementServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to InstanceManagementServiceServer will
// result in compilation errors.
type UnsafeInstanceManagementServiceServer interface {
	mustEmbedUnimplementedInstanceManagementServiceServer()
}

func RegisterInstanceManagementServiceServer(s grpc.ServiceRegistrar, srv InstanceManagementServiceServer) {
	s.RegisterService(&InstanceManagementService_ServiceDesc, srv)
}

func _InstanceManagementService_ListInstance_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListInstanceReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(InstanceManagementServiceServer).ListInstance(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/v2ray.core.app.instman.command.InstanceManagementService/ListInstance",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(InstanceManagementServiceServer).ListInstance(ctx, req.(*ListInstanceReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _InstanceManagementService_AddInstance_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AddInstanceReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(InstanceManagementServiceServer).AddInstance(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/v2ray.core.app.instman.command.InstanceManagementService/AddInstance",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(InstanceManagementServiceServer).AddInstance(ctx, req.(*AddInstanceReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _InstanceManagementService_StartInstance_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StartInstanceReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(InstanceManagementServiceServer).StartInstance(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/v2ray.core.app.instman.command.InstanceManagementService/StartInstance",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(InstanceManagementServiceServer).StartInstance(ctx, req.(*StartInstanceReq))
	}
	return interceptor(ctx, in, info, handler)
}

// InstanceManagementService_ServiceDesc is the grpc.ServiceDesc for InstanceManagementService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var InstanceManagementService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "v2ray.core.app.instman.command.InstanceManagementService",
	HandlerType: (*InstanceManagementServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ListInstance",
			Handler:    _InstanceManagementService_ListInstance_Handler,
		},
		{
			MethodName: "AddInstance",
			Handler:    _InstanceManagementService_AddInstance_Handler,
		},
		{
			MethodName: "StartInstance",
			Handler:    _InstanceManagementService_StartInstance_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "app/instman/command/command.proto",
}
