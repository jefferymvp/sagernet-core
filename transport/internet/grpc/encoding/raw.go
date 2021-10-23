package encoding

import (
	"context"
	"github.com/v2fly/v2ray-core/v4/common/buf"
	"github.com/v2fly/v2ray-core/v4/common/bytesgrp"
	"github.com/v2fly/v2ray-core/v4/common/net"
	"github.com/v2fly/v2ray-core/v4/common/signal/done"
	"github.com/v2fly/v2ray-core/v4/transport/internet"
	"google.golang.org/grpc/encoding"
	"io"
)

func init() {
	encoding.RegisterCodec(rawCodec{})
}

var _ encoding.Codec = (*rawCodec)(nil)

type rawMessage struct {
	data [][]byte
}

type rawCodec struct {
}

func (b rawCodec) Name() string {
	return "raw"
}

func (b rawCodec) Marshal(v interface{}) ([]byte, error) {
	return bytesgrp.Pack(v.(rawMessage).data), nil
}

func (b rawCodec) Unmarshal(data []byte, v interface{}) error {
	v.(*rawMessage).data = bytesgrp.UnPack(data)
	return nil
}

type Stream interface {
	Context() context.Context
	SendMsg(m interface{}) error
	RecvMsg(m interface{}) error
}

type SendCloser interface {
	CloseSend() error
}

type RawClient struct {
	stream Stream
	done   *done.Instance

	buf   [][]byte
	index int
}

func NewRawConn(stream Stream) internet.Connection {
	c := &RawClient{stream: stream, done: done.New()}
	return net.NewConnection(net.ConnectionOutputMulti(c), net.ConnectionInputMulti(c), net.ConnectionOnClose(c))
}

func (h *RawClient) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if h.done.Done() {
		return nil, io.EOF
	}
	message := new(rawMessage)
	err := h.stream.RecvMsg(message)
	if err == io.EOF {
		return nil, err
	} else if err != nil {
		return nil, newError("failed to fetch data from gRPC tunnel").Base(err)
	}

	mb := buf.MultiBuffer{}
	for _, data := range message.data {
		if len(data) == 0 {
			continue
		}
		mb = buf.MergeBytes(mb, data)
	}
	return mb, nil
}

func (h *RawClient) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	if h.done.Done() {
		return io.ErrClosedPipe
	}

	hunks := make([][]byte, 0, len(mb))
	for _, b := range mb {
		if b.Len() > 0 {
			hunks = append(hunks, b.Bytes())
		}
	}
	return h.stream.SendMsg(&rawMessage{hunks})
}

func (h *RawClient) Close() error {
	if h.done.Done() {
		return nil
	}

	if c, ok := h.stream.(SendCloser); ok {
		return c.CloseSend()
	}

	return h.done.Close()
}
