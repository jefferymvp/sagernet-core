// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.19.4
// source: common/taggedfeatures/skeleton.proto

package taggedfeatures

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	anypb "google.golang.org/protobuf/types/known/anypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Config struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Features map[string]*anypb.Any `protobuf:"bytes,1,rep,name=features,proto3" json:"features,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_common_taggedfeatures_skeleton_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_common_taggedfeatures_skeleton_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Config.ProtoReflect.Descriptor instead.
func (*Config) Descriptor() ([]byte, []int) {
	return file_common_taggedfeatures_skeleton_proto_rawDescGZIP(), []int{0}
}

func (x *Config) GetFeatures() map[string]*anypb.Any {
	if x != nil {
		return x.Features
	}
	return nil
}

var File_common_taggedfeatures_skeleton_proto protoreflect.FileDescriptor

var file_common_taggedfeatures_skeleton_proto_rawDesc = []byte{
	0x0a, 0x24, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x74, 0x61, 0x67, 0x67, 0x65, 0x64, 0x66,
	0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x2f, 0x73, 0x6b, 0x65, 0x6c, 0x65, 0x74, 0x6f, 0x6e,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x20, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f,
	0x72, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x74, 0x61, 0x67, 0x67, 0x65, 0x64,
	0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x1a, 0x19, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x61, 0x6e, 0x79, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0xaf, 0x01, 0x0a, 0x06, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x52,
	0x0a, 0x08, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x36, 0x2e, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f,
	0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x74, 0x61, 0x67, 0x67, 0x65, 0x64, 0x66, 0x65, 0x61, 0x74, 0x75,
	0x72, 0x65, 0x73, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x46, 0x65, 0x61, 0x74, 0x75,
	0x72, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x08, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72,
	0x65, 0x73, 0x1a, 0x51, 0x0a, 0x0d, 0x46, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x45, 0x6e,
	0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x2a, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x41, 0x6e, 0x79, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x81, 0x01, 0x0a, 0x24, 0x63, 0x6f, 0x6d, 0x2e, 0x76, 0x32,
	0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e,
	0x74, 0x61, 0x67, 0x67, 0x65, 0x64, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x50, 0x01,
	0x5a, 0x34, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x76, 0x32, 0x66,
	0x6c, 0x79, 0x2f, 0x76, 0x32, 0x72, 0x61, 0x79, 0x2d, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x35,
	0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x74, 0x61, 0x67, 0x67, 0x65, 0x64, 0x66, 0x65,
	0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0xaa, 0x02, 0x20, 0x56, 0x32, 0x52, 0x61, 0x79, 0x2e, 0x43,
	0x6f, 0x72, 0x65, 0x2e, 0x43, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x54, 0x61, 0x67, 0x67, 0x65,
	0x64, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_common_taggedfeatures_skeleton_proto_rawDescOnce sync.Once
	file_common_taggedfeatures_skeleton_proto_rawDescData = file_common_taggedfeatures_skeleton_proto_rawDesc
)

func file_common_taggedfeatures_skeleton_proto_rawDescGZIP() []byte {
	file_common_taggedfeatures_skeleton_proto_rawDescOnce.Do(func() {
		file_common_taggedfeatures_skeleton_proto_rawDescData = protoimpl.X.CompressGZIP(file_common_taggedfeatures_skeleton_proto_rawDescData)
	})
	return file_common_taggedfeatures_skeleton_proto_rawDescData
}

var file_common_taggedfeatures_skeleton_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_common_taggedfeatures_skeleton_proto_goTypes = []interface{}{
	(*Config)(nil),    // 0: v2ray.core.common.taggedfeatures.Config
	nil,               // 1: v2ray.core.common.taggedfeatures.Config.FeaturesEntry
	(*anypb.Any)(nil), // 2: google.protobuf.Any
}
var file_common_taggedfeatures_skeleton_proto_depIdxs = []int32{
	1, // 0: v2ray.core.common.taggedfeatures.Config.features:type_name -> v2ray.core.common.taggedfeatures.Config.FeaturesEntry
	2, // 1: v2ray.core.common.taggedfeatures.Config.FeaturesEntry.value:type_name -> google.protobuf.Any
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_common_taggedfeatures_skeleton_proto_init() }
func file_common_taggedfeatures_skeleton_proto_init() {
	if File_common_taggedfeatures_skeleton_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_common_taggedfeatures_skeleton_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Config); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_common_taggedfeatures_skeleton_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_common_taggedfeatures_skeleton_proto_goTypes,
		DependencyIndexes: file_common_taggedfeatures_skeleton_proto_depIdxs,
		MessageInfos:      file_common_taggedfeatures_skeleton_proto_msgTypes,
	}.Build()
	File_common_taggedfeatures_skeleton_proto = out.File
	file_common_taggedfeatures_skeleton_proto_rawDesc = nil
	file_common_taggedfeatures_skeleton_proto_goTypes = nil
	file_common_taggedfeatures_skeleton_proto_depIdxs = nil
}
