package proxy

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"
)

type Server struct {
	ports        map[int]bool
	logger       *slog.Logger
	slots        chan struct{}
	allowPrivate bool
	local        []netip.Prefix
}

func NewServer(ports map[int]bool, logger *slog.Logger) *Server {
	return &Server{ports: ports, logger: logger, slots: make(chan struct{}, maxTunnels)}
}

func (s *Server) RefuseLocalPrefixes() error {
	var err error
	s.local, err = localPrefixes()
	return err
}

func (s *Server) LocalPrefixes() []netip.Prefix { return s.local }

func (s *Server) HTTPServer() *http.Server {
	server := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: headerTimeout,
		ErrorLog:          slog.NewLogLogger(s.logger.Handler(), slog.LevelWarn),
	}
	server.Protocols = new(http.Protocols)
	server.Protocols.SetHTTP1(true)
	return server
}

func reject(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Connection", "close")
	http.Error(w, message, status)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		w.Header().Set("Allow", http.MethodConnect)
		reject(w, http.StatusMethodNotAllowed, "only CONNECT is supported")
		return
	}
	host, port, err := parseConnectTarget(r)
	if err != nil {
		reject(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.ports[port] {
		reject(w, http.StatusForbidden, "destination port not allowed")
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		reject(w, http.StatusServiceUnavailable, "tunnel limit reached")
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	upstream, err := s.dial(r.Context(), target)
	if err != nil {
		status := http.StatusBadGateway
		var netErr net.Error
		if errors.Is(err, errPrivateDestination) {
			status = http.StatusForbidden
		} else if errors.As(err, &netErr) && netErr.Timeout() {
			status = http.StatusGatewayTimeout
		}
		s.logger.Warn("connect failed", "client", r.RemoteAddr, "target", target, "error", err)
		reject(w, status, http.StatusText(status))
		return
	}
	defer upstream.Close()
	client, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		s.logger.Warn("hijack failed", "error", err)
		return
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(headerTimeout))
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	started := time.Now()
	s.logger.Info("tunnel opened", "client", r.RemoteAddr, "target", target)
	pipe(client, buffered.Reader, upstream, upstream)
	s.logger.Info("tunnel closed", "client", r.RemoteAddr, "target", target, "duration", time.Since(started))
}
