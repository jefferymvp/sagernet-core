package simpleobfs

import (
	"github.com/v2fly/v2ray-core/v4/common/buf"
	"io"
	"sync"
)

type cachedReader struct {
	io.Reader
	sync.Mutex
	cached   buf.MultiBuffer
	released bool
}

func (c *cachedReader) Read(p []byte) (n int, err error) {
	n, err = c.Reader.Read(p)
	if !c.released && err == nil && n > 0 {
		c.Lock()
		if !c.released {
			if c.cached == nil {
				c.cached = buf.MultiBuffer{buf.From(p[:n])}
			} else {
				c.cached = append(c.cached, buf.From(p[:n]))
			}
		}
		c.Unlock()
	}
	return
}

func (c *cachedReader) cachedBytes() buf.MultiBuffer {
	c.Lock()
	defer c.Unlock()

	if !c.released {
		c.released = true
	}

	return c.cached
}

func (c *cachedReader) release()  {
	mb := c.cachedBytes()
	if mb != nil {
		buf.ReleaseMulti(mb)
	}
}