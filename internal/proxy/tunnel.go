package proxy

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type activity struct {
	io.Reader
	touch func()
}

func (a activity) Read(p []byte) (int, error) {
	n, err := a.Reader.Read(p)
	if n > 0 {
		a.touch()
	}
	return n, err
}

func pipe(a net.Conn, aReader io.Reader, b net.Conn, bReader io.Reader, idle time.Duration) {
	touch := func() {
		deadline := time.Now().Add(idle)
		_ = a.SetReadDeadline(deadline)
		_ = b.SetReadDeadline(deadline)
	}
	touch()
	var wg sync.WaitGroup
	wg.Go(func() { pipeOneWay(b, activity{aReader, touch}, a) })
	wg.Go(func() { pipeOneWay(a, activity{bReader, touch}, b) })
	wg.Wait()
}

func pipeOneWay(dst net.Conn, src io.Reader, srcConn net.Conn) {
	_, err := io.Copy(dst, src)
	if err == nil {
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			err = cw.CloseWrite()
		} else {
			err = errors.ErrUnsupported
		}
	}
	if err != nil {
		dst.Close()
		srcConn.Close()
	}
}
