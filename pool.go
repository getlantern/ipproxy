package ipproxy

import (
	"sync"
)

const maxUDPPacketSize = 1 << 17

// Buffer pool for forwarding UDP packets
var bytesPool = sync.Pool{
	New: func() any {
		b := make([]byte, maxUDPPacketSize)
		return &b
	},
}

func acquire() *[]byte {
	return bytesPool.Get().(*[]byte)
}

func release(buf *[]byte) {
	bytesPool.Put(buf)
}
