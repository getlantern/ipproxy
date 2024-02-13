package ipproxy

import (
	"net"
	"sync"
	"time"
)

func copyBuffer(src, dst net.Conn, buf []byte, timeout time.Duration) {
    for {
        src.SetReadDeadline(time.Now().Add(timeout))
        dst.SetWriteDeadline(time.Now().Add(timeout))
        nr, err := src.Read(buf)
        if err != nil {
            break
        }
        _, err = dst.Write(buf[0:nr])
        if err != nil {
            break
        }
    }
}

func relay(left, right net.Conn, waitTimeout time.Duration) {
    wg := sync.WaitGroup {}
    wg.Add(2)

    go func() {
        defer wg.Done()
        buf := acquireBuffer()
        defer releaseBuffer(buf)

        copyBuffer(right, left, buf, waitTimeout)
    }()

    go func() {
        defer wg.Done()
        buf := acquireBuffer()
        defer releaseBuffer(buf)

        copyBuffer(left, right, buf, waitTimeout)
    }()

    wg.Wait()
}