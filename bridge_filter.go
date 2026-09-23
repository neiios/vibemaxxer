package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"
)

const bridgeHeaderLimit = 16 << 10

// filterCONNECT reads only the first request header. The original header and
// any read-ahead bytes are replayed unchanged for the server to process.
func (b *bridge) filterCONNECT(local net.Conn) (io.Reader, error) {
	_ = local.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer local.SetReadDeadline(time.Time{})
	reject := func(status int, message string) (io.Reader, error) {
		_ = local.SetWriteDeadline(time.Now().Add(10 * time.Second))
		defer local.SetWriteDeadline(time.Time{})
		_, _ = fmt.Fprintf(local, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", status, http.StatusText(status), len(message), message)
		return nil, fmt.Errorf("%s", message)
	}
	reader := bufio.NewReader(local)
	var header []byte
	for !bytes.HasSuffix(header, []byte("\r\n\r\n")) {
		if len(header) == bridgeHeaderLimit {
			return reject(http.StatusRequestHeaderFieldsTooLarge, "CONNECT header too large\n")
		}
		c, err := reader.ReadByte()
		if err != nil {
			return reject(http.StatusBadRequest, "incomplete CONNECT header\n")
		}
		header = append(header, c)
	}
	r, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(header)))
	if err != nil {
		return reject(http.StatusBadRequest, "invalid CONNECT request\n")
	}
	if r.Method != http.MethodConnect {
		return reject(http.StatusMethodNotAllowed, "only CONNECT is supported\n")
	}
	host, portText, err := net.SplitHostPort(r.RequestURI)
	port, portErr := strconv.Atoi(portText)
	if err != nil || host == "" || portErr != nil || port < 1 || port > 65535 ||
		r.URL.Host != r.RequestURI || r.URL.Scheme != "" || r.ContentLength > 0 || len(r.TransferEncoding) != 0 {
		return reject(http.StatusBadRequest, "expected CONNECT hostname:port without a request body\n")
	}
	if addr, err := netip.ParseAddr(host); err == nil && addr.Zone() == "" {
		// Domain rules deliberately do not govern IP-literal destinations.
	} else {
		host, err = normalizeDomain(host)
		if err != nil {
			return reject(http.StatusBadRequest, "invalid destination domain\n")
		}
		if rule := b.blocklist.match(host); rule != "" {
			b.logger.Info("destination domain blocked", "client", local.RemoteAddr(), "target", r.RequestURI, "rule", rule)
			return reject(http.StatusForbidden, "destination domain blocked\n")
		}
	}
	return io.MultiReader(bytes.NewReader(header), reader), nil
}
