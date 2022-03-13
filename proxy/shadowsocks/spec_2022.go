package shadowsocks

import (
	"crypto/cipher"
	"github.com/v2fly/v2ray-core/v5/common/antireplay"
	"github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/v2fly/v2ray-core/v5/common/crypto"
	"github.com/v2fly/v2ray-core/v5/common/protocol"
	"io"
	"lukechampine.com/blake3"
)

const (
	HeaderTypeServerStream = 0
	HeaderTypeClientStream = 1
	MaxPaddingLength       = 900
	SaltSize               = 32
	MinRequestHeaderSize   = 1 + 8
	MinResponseHeaderSize  = MinRequestHeaderSize + SaltSize
)

var _ Cipher = (*AEAD2022Cipher)(nil)

type AEAD2022Cipher struct {
	KeyBytes        int32
	AEADAuthCreator func(key []byte) cipher.AEAD
}

func newFilter() *antireplay.ReplayFilter {
	return antireplay.NewReplayFilter(30)
}

func (*AEAD2022Cipher) Family() CipherFamily {
	return CipherFamilyAEADSpec2022
}

func (c *AEAD2022Cipher) KeySize() int32 {
	return c.KeyBytes
}

func (c *AEAD2022Cipher) IVSize() int32 {
	return SaltSize
}

func (c *AEAD2022Cipher) createAuthenticator(key []byte, iv []byte) *crypto.AEADAuthenticator {
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
	auth := c.createAuthenticator(key, iv)
	return crypto.NewAuthenticationWriter(auth, &crypto.AEADChunkSizeParser{
		Auth: auth,
	}, writer, protocol.TransferTypeStream, nil), nil
}

func (c *AEAD2022Cipher) NewDecryptionReader(key []byte, iv []byte, reader io.Reader) (buf.Reader, error) {
	auth := c.createAuthenticator(key, iv)
	return crypto.NewAuthenticationReader(auth, &crypto.AEADChunkSizeParser{
		Auth: auth,
	}, reader, protocol.TransferTypeStream, nil), nil
}

func (c *AEAD2022Cipher) EncodePacket(key []byte, b *buf.Buffer) error {
	ivLen := c.IVSize()
	payloadLen := b.Len()
	auth := c.createAuthenticator(key, b.BytesTo(ivLen))

	b.Extend(int32(auth.Overhead()))
	_, err := auth.Seal(b.BytesTo(ivLen), b.BytesRange(ivLen, payloadLen))
	return err
}

func (c *AEAD2022Cipher) DecodePacket(key []byte, b *buf.Buffer) error {
	if b.Len() <= c.IVSize() {
		return newError("insufficient data: ", b.Len())
	}
	ivLen := c.IVSize()
	payloadLen := b.Len()
	auth := c.createAuthenticator(key, b.BytesTo(ivLen))

	bbb, err := auth.Open(b.BytesTo(ivLen), b.BytesRange(ivLen, payloadLen))
	if err != nil {
		return err
	}
	b.Resize(ivLen, int32(len(bbb)))
	return nil
}

func deriveKey(secret, salt, outKey []byte) {
	sessionKey := make([]byte, len(secret)+len(salt))
	copy(sessionKey, secret)
	copy(sessionKey[len(secret):], salt)
	blake3.DeriveKey(outKey, "shadowsocks 2022 session subkey", sessionKey)
}
