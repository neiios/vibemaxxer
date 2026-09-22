package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

const invitationPrefix = "vibemaxxer-pair-v1:"
const maxInvitationSize = 4096

type invitation struct {
	Version   int       `json:"version"`
	Address   string    `json:"address"`
	ServerKey string    `json:"server_key"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
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

func makeInvitation(store *stateStore, id *identity, ttl time.Duration) (string, error) {
	if ttl < time.Minute || ttl > time.Hour {
		return "", errors.New("invitation lifetime must be between 1m and 1h")
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	invite := invitation{
		Version: 1, ServerKey: id.fingerprint(), Token: base64.RawURLEncoding.EncodeToString(random),
		ExpiresAt: time.Now().Add(ttl),
	}
	if err := store.updateServer(func(state *serverState) error {
		if err := validEndpoint(state.Address); err != nil {
			return err
		}
		invite.Address = state.Address
		state.Pending = &pendingInvitation{TokenHash: tokenHash(invite.Token), ExpiresAt: invite.ExpiresAt}
		return nil
	}); err != nil {
		return "", fmt.Errorf("create invitation (start 'serve' first): %w", err)
	}
	data, err := json.Marshal(invite)
	if err != nil {
		return "", err
	}
	return invitationPrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

func decodeInvitation(code string) (invitation, error) {
	var invite invitation
	code = strings.TrimSpace(code)
	if len(code) > maxInvitationSize || !strings.HasPrefix(code, invitationPrefix) {
		return invite, errors.New("invalid pairing invitation")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, invitationPrefix))
	if err != nil {
		return invite, errors.New("invalid pairing invitation encoding")
	}
	if err := json.Unmarshal(data, &invite); err != nil || invite.Version != 1 || !validFingerprint(invite.ServerKey) {
		return invite, errors.New("invalid or unsupported pairing invitation")
	}
	if err := validEndpoint(invite.Address); err != nil {
		return invite, err
	}
	token, err := base64.RawURLEncoding.DecodeString(invite.Token)
	if err != nil || len(token) != 32 {
		return invite, errors.New("invalid invitation token")
	}
	if !time.Now().Before(invite.ExpiresAt) {
		return invite, errors.New("pairing invitation has expired")
	}
	return invite, nil
}

var errEnrollmentDenied = errors.New("invalid, expired, or already used invitation")
var errClientName = errors.New("client name already belongs to another identity")

func enroll(store *stateStore, key string, request pairRequest) error {
	if !validFingerprint(key) || !validClientName(request.Name) {
		return errors.New("invalid client identity or name")
	}
	return store.updateServer(func(state *serverState) error {
		pending := state.Pending
		if pending == nil || !time.Now().Before(pending.ExpiresAt) ||
			subtle.ConstantTimeCompare([]byte(tokenHash(request.Token)), []byte(pending.TokenHash)) != 1 {
			return errEnrollmentDenied
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
		transport := &http.Transport{
			// Never inherit HTTP_PROXY: enrollment must connect to the pinned server.
			TLSClientConfig:     id.clientTLS(invite.ServerKey),
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
		config := bridgeState{Version: 1, Address: invite.Address, ServerKey: invite.ServerKey}
		if err := store.write("bridge.json", config); err != nil {
			return fmt.Errorf("server registered this client, but local state could not be saved; fix storage and create a new invitation: %w", err)
		}
		return nil
	})
}
