package ipproxy

import (
	"sync"
)

// closeable is a helper type for asynchronous processes that follow an orderly
// close sequence.
type closeable struct {
	finalizer         func() error
	closeCh           chan struct{}
	readyToFinalizeCh chan struct{}
	closedCh          chan struct{}
	closeNowOnce      sync.Once
	closeOnce         sync.Once
}

func (cl *closeable) Close() (err error) {
	cl.closeOnce.Do(func() {
		close(cl.closeCh)
		<-cl.readyToFinalizeCh
		if cl.finalizer != nil {
			err = cl.finalizer()
		}
		close(cl.closedCh)
		if err != nil {
			log.Error(err)
		}
	})
	return
}

func (cl *closeable) closeNow() (err error) {
	cl.closeNowOnce.Do(func() {
		close(cl.readyToFinalizeCh)
		err = cl.Close()
	})
	return err
}
