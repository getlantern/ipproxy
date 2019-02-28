package ipproxy

import (
	"sync"
)

// closeable is a helper type for asynchronous processes that follow an orderly
// close sequence.
type closeable struct {
	closeCh   chan struct{}
	closedCh  chan error
	closeOnce sync.Once
}

func (cl *closeable) Close() (err error) {
	cl.closeOnce.Do(func() {
		close(cl.closeCh)
		err = <-cl.closedCh
	})
	return
}
