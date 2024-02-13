package ipproxy

import (
    "sync"
)

const bufferSize = 1 << 17

// Buffer pool for forwarding UDP packets
var udpBufPool = sync.Pool {
    New: func() interface {} {
        return make([]byte, bufferSize)
    },
}

func acquireBuffer() []byte {
    return udpBufPool.Get().([]byte)
}

func releaseBuffer(buf []byte) {
    udpBufPool.Put(buf)
}
