package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"math/rand"
	"sync/atomic"

	"lukechampine.com/blake3"

	"github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/v2fly/v2ray-core/v5/common/crypto"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/protocol"
	"github.com/v2fly/v2ray-core/v5/proxy/socks"
)

const (
	HeaderTypeClient       = 0
	HeaderTypeServer       = 1
	HeaderTypeClientPacket = 2
	HeaderTypeServerPacket = 3
	MaxPaddingLength       = 900
	SaltSize               = 32
	PacketNonceSize        = 24
	MinRequestHeaderSize   = 1 + 8
	MinResponseHeaderSize  = MinRequestHeaderSize + SaltSize
)

var _ Cipher = (*AEAD2022Cipher)(nil)

type AEAD2022Cipher struct {
	KeyBytes           int32
	AEADAuthCreator    func(key []byte) cipher.AEAD
	UDPBlockCreator    func(key []byte) cipher.Block
	UDPAEADAuthCreator func(key []byte) cipher.AEAD
}

func (c *AEAD2022Cipher) Family() CipherFamily {
	if c.UDPBlockCreator != nil {
		return CipherFamilyAEADSpec2022UDPBlock
	} else {
		return CipherFamilyAEADSpec2022
	}
}

func (c *AEAD2022Cipher) KeySize() int32 {
	return c.KeyBytes
}

func (c *AEAD2022Cipher) IVSize() int32 {
	return SaltSize
}

func (c *AEAD2022Cipher) tcpAuthenticator(key []byte, iv []byte) *crypto.AEADAuthenticator {
	subkey := make([]byte, c.KeyBytes)
	deriveKey(key, iv, subkey)
	aead := c.AEADAuthCreator(subkey)
	nonce := crypto.GenerateAEADNonceWithSize(aead.NonceSize())
	return &crypto.AEADAuthenticator{
		AEAD:           aead,
		NonceGenerator: nonce,
	}
}

func (c *AEAD2022Cipher) NewEncryptionWriter(key []byte, iv []byte, writer io.Writer) (buf.Writer, error) {
	auth := c.tcpAuthenticator(key, iv)
	return crypto.NewAuthenticationWriter(auth, &crypto.AEADChunkSizeParser{
		Auth: auth,
	}, writer, protocol.TransferTypeStream, nil), nil
}

func (c *AEAD2022Cipher) NewDecryptionReader(key []byte, iv []byte, reader io.Reader) (buf.Reader, error) {
	auth := c.tcpAuthenticator(key, iv)
	return crypto.NewAuthenticationReader(auth, &crypto.AEADChunkSizeParser{
		Auth: auth,
	}, reader, protocol.TransferTypeStream, nil), nil
}

func (c *AEAD2022Cipher) EncodePacket(key []byte, b *buf.Buffer) error {
	payloadLen := b.Len()
	if c.UDPBlockCreator != nil {
		// aes
		packetHeader := b.BytesTo(aes.BlockSize)
		subKey := make([]byte, c.KeyBytes)
		deriveKey(key, packetHeader[:8], subKey)

		auth := &crypto.AEADAuthenticator{
			AEAD:           c.AEADAuthCreator(subKey),
			NonceGenerator: crypto.GenerateStaticBytes(packetHeader[4:16]),
		}

		b.Extend(int32(auth.Overhead()))
		_, err := auth.Seal(b.BytesTo(aes.BlockSize), b.BytesRange(aes.BlockSize, payloadLen))
		c.UDPBlockCreator(key).Encrypt(packetHeader, packetHeader)
		return err
	} else {
		// xchacha
		auth := &crypto.AEADAuthenticator{
			AEAD:           c.UDPAEADAuthCreator(key),
			NonceGenerator: crypto.GenerateStaticBytes(b.BytesTo(PacketNonceSize)),
		}
		b.Extend(int32(auth.Overhead()))
		_, err := auth.Seal(b.BytesTo(PacketNonceSize), b.BytesRange(PacketNonceSize, payloadLen))
		return err
	}
}

func (c *AEAD2022Cipher) DecodePacket(key []byte, b *buf.Buffer) error {
	var nonceIndex int32
	var nonceLen int32
	payloadLen := b.Len()
	var auth *crypto.AEADAuthenticator
	if c.UDPBlockCreator != nil {
		if b.Len() <= aes.BlockSize {
			return newError("insufficient data: ", b.Len())
		}
		packetHeader := b.BytesTo(aes.BlockSize)
		c.UDPBlockCreator(key).Decrypt(packetHeader, packetHeader)
		subKey := make([]byte, c.KeyBytes)
		deriveKey(key, packetHeader[:8], subKey)
		auth = &crypto.AEADAuthenticator{
			AEAD:           c.AEADAuthCreator(subKey),
			NonceGenerator: crypto.GenerateStaticBytes(packetHeader[4:16]),
		}
		nonceIndex = 0
		nonceLen = 16
	} else {
		auth = &crypto.AEADAuthenticator{
			AEAD:           c.UDPAEADAuthCreator(key),
			NonceGenerator: crypto.GenerateStaticBytes(b.BytesTo(PacketNonceSize)),
		}
		nonceIndex = PacketNonceSize
		nonceLen = PacketNonceSize
	}
	bbb, err := auth.Open(b.BytesTo(nonceLen), b.BytesRange(nonceLen, payloadLen))
	if err != nil {
		return err
	}
	b.Resize(nonceIndex, int32(len(bbb)))
	return nil
}

func deriveKey(secret, salt, outKey []byte) {
	sessionKey := make([]byte, len(secret)+len(salt))
	copy(sessionKey, secret)
	copy(sessionKey[len(secret):], salt)
	blake3.DeriveKey(outKey, "shadowsocks 2022 session subkey", sessionKey)
}

type udpSession struct {
	sessionId           uint64
	packetId            uint64
	headerType          byte
	remoteSessionId     uint64
	lastRemoteSessionId uint64
}

func (s *udpSession) nextPacketId() uint64 {
	return atomic.AddUint64(&s.packetId, 1)
}

func newUDPSession(server bool) *udpSession {
	s := new(udpSession)
	s.sessionId = rand.Uint64()
	if server {
		s.headerType = HeaderTypeServer
		s.packetId = 1<<63 - 1
	}
	return s
}

type UoTReader struct {
	io.Reader
}

func NewUoTReader(reader io.Reader) *UoTReader {
	return &UoTReader{Reader: reader}
}

func NewBufferedUoTReader(reader buf.Reader) *UoTReader {
	return &UoTReader{Reader: &buf.BufferedReader{Reader: reader}}
}

func (r *UoTReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	buffer := buf.New()
	var length uint16
	err := binary.Read(r, binary.BigEndian, &length)
	if err != nil {
		buffer.Release()
		return nil, err
	}
	_, err = io.ReadFull(r, buffer.Extend(int32(length)))
	if err != nil {
		buffer.Release()
		return nil, err
	}
	addr, port, err := socks.AddrParser.ReadAddressPort(nil, buffer)
	if err != nil {
		buffer.Release()
		return nil, err
	}
	endpoint := net.UDPDestination(addr, port)
	buffer.Endpoint = &endpoint
	return buf.MultiBuffer{buffer}, nil
}

type UoTWriter struct {
	io.Writer
	Flusher buf.Flusher
	Request *net.Destination
}

func NewUoTWriter(writer io.Writer, request *net.Destination) *UoTWriter {
	w := &UoTWriter{
		Writer:  writer,
		Request: request,
	}
	if flusher, ok := writer.(buf.Flusher); ok {
		w.Flusher = flusher
	}
	return w
}

func NewBufferedUoTWriter(writer buf.Writer, request *net.Destination) *UoTWriter {
	bufferedWriter := buf.NewBufferedWriter(writer)
	return &UoTWriter{
		Writer:  bufferedWriter,
		Flusher: bufferedWriter,
		Request: request,
	}
}

func (w *UoTWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, packet := range mb {
		if packet.Endpoint == nil {
			packet.Endpoint = w.Request
			if w.Request == nil {
				return newError("empty packet destination")
			}
		}
		header := buf.New()
		defer header.Release()
		err := socks.AddrParser.WriteAddressPort(header, packet.Endpoint.Address, packet.Endpoint.Port)
		if err != nil {
			return err
		}
		err = binary.Write(header, binary.BigEndian, uint16(header.Len()+packet.Len()))
		if err != nil {
			return err
		}
		_, err = w.Write(header.Bytes())
		if err != nil {
			return err
		}
		_, err = w.Write(packet.Bytes())
		if err != nil {
			return err
		}
	}
	if w.Flusher != nil {
		return w.Flusher.Flush()
	}
	return nil
}

type UoTTransportReader struct {
	buf.Reader
}

func NewUoTTransportReader(reader buf.Reader) *UoTTransportReader {
	return &UoTTransportReader{reader}
}

func (r *UoTTransportReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if err != nil {
		return nil, err
	}
	mbret := make(buf.MultiBuffer, 0, mb.Len()*2)
	index := 0
	for _, buffer := range mb {
		if buffer.Endpoint == nil {
			buf.ReleaseMulti(mb)
			buf.ReleaseMulti(mbret)
			return nil, newError("empty udp endpoint")
		}
		header := buf.New()
		length := buffer.Extend(2)
		socks.AddrParser.WriteAddressPort(header, buffer.Endpoint.Address, buffer.Endpoint.Port)
		binary.BigEndian.PutUint16(length, uint16(header.Len()-2+buffer.Len()))
		mbret[index*2] = header
		mbret[index*2+1] = buffer
		index++
	}
	return mbret, nil
}
