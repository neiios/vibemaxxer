package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	dialTimeout   = 10 * time.Second
	headerTimeout = 10 * time.Second
	maxTunnels    = 256
)

func ParsePorts(value string) (map[int]bool, error) {
	ports := make(map[int]bool)
	for _, part := range strings.Split(value, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid destination port %q", part)
		}
		ports[port] = true
	}
	return ports, nil
}

func ValidEndpoint(address string) error {
	host, portText, err := net.SplitHostPort(address)
	port, portErr := strconv.Atoi(portText)
	if err != nil || host == "" || portErr != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%q must be HOST:PORT", address)
	}
	return nil
}

func parseConnectTarget(r *http.Request) (host string, port int, err error) {
	host, portText, err := net.SplitHostPort(r.URL.Host)
	if err != nil {
		return "", 0, errors.New("expected CONNECT host:port")
	}
	port, err = strconv.Atoi(portText)
	if err != nil || host == "" || port < 1 || port > 65535 {
		return "", 0, errors.New("expected CONNECT host:port")
	}
	return host, port, nil
}

func respond(conn net.Conn, status int, message string) {
	_ = conn.SetWriteDeadline(time.Now().Add(headerTimeout))
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s\n",
		status, http.StatusText(status), len(message)+1, message)
}

func pipe(a net.Conn, aReader io.Reader, b net.Conn, bReader io.Reader) {
	var wg sync.WaitGroup
	wg.Add(2)
	go pipeOneWay(&wg, b, aReader, a)
	go pipeOneWay(&wg, a, bReader, b)
	wg.Wait()
	a.Close()
	b.Close()
}

func pipeOneWay(wg *sync.WaitGroup, dst net.Conn, src io.Reader, srcConn net.Conn) {
	defer wg.Done()
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
