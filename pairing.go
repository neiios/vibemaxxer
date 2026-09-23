package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

type invitation struct {
	Address   string
	ServerKey string // Optional out-of-band pin; otherwise pin the authenticated TLS peer after enrollment.
	Token     string
}

type pairRequest struct {
	Token string `json:"token"`
	Name  string `json:"name"`
}

func validEndpoint(address string) error {
	host, portText, err := net.SplitHostPort(address)
	port, portErr := strconv.Atoi(portText)
	if err != nil || host == "" || strings.ContainsAny(host, "/?#@\\% \t\r\n") || portErr != nil || port < 1 || port > 65535 {
		return errors.New("server address must be a hostname or IP with a nonzero port")
	}
	if addr, err := netip.ParseAddr(host); err == nil && (addr.Unmap().IsUnspecified() || addr.Unmap().IsMulticast()) {
		return errors.New("cannot advertise an unspecified or multicast address; use -advertise with a reachable address")
	}
	return nil
}

func validClientName(name string) bool {
	if len(name) < 1 || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func tokenHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func validPairCode(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, digit := range code {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

func makeInvitation(store *stateStore, ttl time.Duration) (string, error) {
	if ttl < time.Minute || ttl > time.Hour {
		return "", errors.New("invitation lifetime must be between 1m and 1h")
	}
	// Rejection sampling in crypto/rand.Int avoids modulo bias; retain leading zeroes.
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	code := fmt.Sprintf("%06d", n.Int64())
	if err := store.updateServer(func(state *serverState) error {
		if err := validEndpoint(state.Address); err != nil {
			return err
		}
		state.Pending = &pendingInvitation{TokenHash: tokenHash(code), ExpiresAt: time.Now().Add(ttl)}
		return nil
	}); err != nil {
		return "", fmt.Errorf("create invitation (start 'serve' first): %w", err)
	}
	return code, nil
}

var errEnrollmentDenied = errors.New("invalid, expired, or already used invitation")
var errClientName = errors.New("client name already belongs to another identity")

func enroll(store *stateStore, key string, request pairRequest) error {
	if !validFingerprint(key) || !validClientName(request.Name) || !validPairCode(request.Token) {
		return errors.New("invalid client identity or name")
	}
	denied := false
	err := store.updateServer(func(state *serverState) error {
		pending := state.Pending
		if pending == nil || !time.Now().Before(pending.ExpiresAt) || pending.Attempts >= 10 {
			return errEnrollmentDenied
		}
		if subtle.ConstantTimeCompare([]byte(tokenHash(request.Token)), []byte(pending.TokenHash)) != 1 {
			pending.Attempts++ // Persist across processes/restarts; bound online guesses.
			denied = true
			return nil
		}
		for existingKey, client := range state.Clients {
			if client.Name == request.Name && existingKey != key {
				return errClientName
			}
		}
		if _, exists := state.Clients[key]; !exists && len(state.Clients) >= 256 {
			return errors.New("client limit reached; revoke an unused client")
		}
		state.Clients[key] = clientRecord{Name: request.Name, AddedAt: time.Now().UTC()}
		state.Pending = nil // Consumed atomically with registration, across processes.
		return nil
	})
	if err == nil && denied {
		return errEnrollmentDenied
	}
	return err
}

type secureHandler struct {
	store *stateStore
	proxy *proxy
}

func (h *secureHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.proxy.clientAllowed(r.RemoteAddr) {
		reject(w, http.StatusForbidden, "client address not allowed")
		return
	}
	if r.TLS == nil {
		reject(w, http.StatusForbidden, "TLS is required")
		return
	}
	key, err := peerIdentity(*r.TLS, x509.ExtKeyUsageClientAuth)
	if err != nil {
		reject(w, http.StatusForbidden, "valid client identity required")
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/pair" {
		// Only this endpoint is accessible to an unpaired TLS identity. Never
		// log request bodies or tokens, and bound slow/oversized request bodies.
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(10 * time.Second))
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		defer r.Body.Close()
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var request pairRequest
		if err := decoder.Decode(&request); err != nil {
			reject(w, http.StatusBadRequest, "invalid pairing request")
			return
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF || !validClientName(request.Name) {
			reject(w, http.StatusBadRequest, "invalid pairing request or client name")
			return
		}
		if err := enroll(h.store, key, request); err != nil {
			status := http.StatusForbidden
			if errors.Is(err, errClientName) {
				status = http.StatusConflict
			}
			reject(w, status, "pairing denied; check invitation and client name")
			return
		}
		h.proxy.logger.Info("client paired", "name", request.Name, "identity", key)
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// Re-read for every CONNECT, including on connections opened before a
	// revocation. Handshake authentication is not sufficient authorization.
	state, err := h.store.readServer()
	if err != nil {
		reject(w, http.StatusServiceUnavailable, "authorization state unavailable")
		return
	}
	if _, ok := state.Clients[key]; !ok {
		reject(w, http.StatusForbidden, "client is not paired")
		return
	}
	h.proxy.ServeHTTP(w, r)
}

// Revocation also terminates established tunnels, normally within one second.
// An unreadable authorization file fails closed, rather than keeping access.
func (h *secureHandler) closeRevoked() {
	state, err := h.store.readServer()
	if err != nil {
		h.proxy.logger.Error("authorization state unavailable; closing tunnels", "error", err)
	}
	h.proxy.mu.Lock()
	var closeList []*tunnel
	for t := range h.proxy.tunnels {
		conn, ok := t.client.(*tls.Conn)
		if !ok {
			closeList = append(closeList, t)
			continue
		}
		key, peerErr := peerIdentity(conn.ConnectionState(), x509.ExtKeyUsageClientAuth)
		if _, allowed := state.Clients[key]; err != nil || peerErr != nil || !allowed {
			closeList = append(closeList, t)
		}
	}
	h.proxy.mu.Unlock()
	for _, t := range closeList {
		t.close()
	}
}

func (h *secureHandler) watchRevocations(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.closeRevoked()
		}
	}
}

func pair(ctx context.Context, store *stateStore, id *identity, invite invitation, name string, replace bool) error {
	if id.fingerprint() == invite.ServerKey {
		return errors.New("server and workstation must use separate identities/state directories")
	}
	if err := validEndpoint(invite.Address); err != nil {
		return err
	}
	if !validPairCode(invite.Token) || invite.ServerKey != "" && !validFingerprint(invite.ServerKey) {
		return errors.New("invalid pairing code or server fingerprint")
	}
	if !validClientName(name) {
		return errors.New("client name must be 1–64 ASCII letters, digits, dots, underscores, or hyphens")
	}
	// Hold the local lock through enrollment, preventing competing pair commands
	// from silently overwriting each other's upstream selection.
	return store.locked(func() error {
		var previous bridgeState
		err := store.read("bridge.json", &previous)
		if err == nil && !replace {
			return errors.New("already paired; use -replace to explicitly replace the saved server")
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		body, _ := json.Marshal(pairRequest{Token: invite.Token, Name: name})
		// The code alone cannot authenticate a server against an active MITM.
		// Verify the identity certificate, and optionally require an out-of-band pin.
		// Only persist the observed key after the server accepts the code.
		var serverKey string
		tlsConfig := id.clientTLS(invite.ServerKey)
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			key, err := peerIdentity(state, x509.ExtKeyUsageServerAuth)
			if err != nil {
				return err
			}
			if key == id.fingerprint() {
				return errors.New("server and workstation must use separate identities/state directories")
			}
			if invite.ServerKey != "" && key != invite.ServerKey {
				return errors.New("server identity does not match supplied fingerprint")
			}
			serverKey = key
			return nil
		}
		transport := &http.Transport{
			// Never inherit HTTP_PROXY: enrollment must connect directly to the server.
			TLSClientConfig:     tlsConfig,
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second, DisableKeepAlives: true,
		}
		defer transport.CloseIdleConnections()
		client := &http.Client{
			Transport: transport, Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+invite.Address+"/pair", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		response, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("pairing connection failed: %w", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			return fmt.Errorf("pairing denied (HTTP %d); check invitation, allowlist, and client name", response.StatusCode)
		}
		config := bridgeState{Version: 1, Address: invite.Address, ServerKey: serverKey}
		if err := store.write("bridge.json", config); err != nil {
			return fmt.Errorf("server registered this client, but local state could not be saved; fix storage and create a new invitation: %w", err)
		}
		return nil
	})
}
