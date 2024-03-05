package ipproxy

import (
	"sync"
)

const maxUDPPacketSize = 1 << 17

// Buffer pool for forwarding UDP packets
var udpBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, maxUDPPacketSize)
		return &b
	},
}

func acquireBuffer() *[]byte {
	return udpBufPool.Get().(*[]byte)
}

func releaseBuffer(buf *[]byte) {
	udpBufPool.Put(buf)
}
