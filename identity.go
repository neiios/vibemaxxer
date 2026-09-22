package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"sync"
	"time"
)

// Trust is attached to the public key, not a CA or a particular certificate.
// Certificates are renewed automatically with the same persistent identity key.
type identity struct {
	key  ed25519.PrivateKey
	mu   sync.Mutex
	cert *tls.Certificate
}

func loadIdentity(store *stateStore) (*identity, error) {
	key, err := store.identityKey()
	if err != nil {
		return nil, err
	}
	return &identity{key: key}, nil
}

func fingerprint(spki []byte) string {
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}

func (id *identity) fingerprint() string {
	spki, _ := x509.MarshalPKIXPublicKey(id.key.Public())
	return fingerprint(spki)
}

func (id *identity) certificate() (*tls.Certificate, error) {
	id.mu.Lock()
	defer id.mu.Unlock()
	now := time.Now()
	if id.cert != nil && now.After(id.cert.Leaf.NotBefore) && now.Add(30*24*time.Hour).Before(id.cert.Leaf.NotAfter) {
		return id.cert, nil
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "vibemaxxer"},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, id.key.Public(), id.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	id.cert = &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: id.key, Leaf: leaf}
	return id.cert, nil
}

func peerIdentity(state tls.ConnectionState, usage x509.ExtKeyUsage) (string, error) {
	if state.Version != tls.VersionTLS13 || len(state.PeerCertificates) != 1 {
		return "", errors.New("TLS 1.3 and one identity certificate are required")
	}
	cert := state.PeerCertificates[0]
	if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
		return "", errors.New("peer identity must be Ed25519")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return "", errors.New("peer certificate is not currently valid; check system clocks")
	}
	if len(cert.UnhandledCriticalExtensions) != 0 || cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return "", errors.New("invalid peer certificate constraints")
	}
	found := false
	for _, value := range cert.ExtKeyUsage {
		found = found || value == usage
	}
	if !found {
		return "", errors.New("peer certificate has incorrect usage")
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return "", errors.New("peer identity certificate is not self-signed")
	}
	return fingerprint(cert.RawSubjectPublicKeyInfo), nil
}

func (id *identity) clientTLS(serverKey string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
		// Deliberately replace Web PKI/hostname validation with an out-of-band
		// SHA-256 SPKI pin AND certificate checks. Never remove VerifyConnection.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			key, err := peerIdentity(state, x509.ExtKeyUsageServerAuth)
			if err != nil {
				return err
			}
			if !validFingerprint(serverKey) || subtle.ConstantTimeCompare([]byte(key), []byte(serverKey)) != 1 {
				return errors.New("server identity does not match pairing; refusing connection")
			}
			return nil
		},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return id.certificate()
		},
	}
}

func (id *identity) serverTLS(store *stateStore) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
		ClientAuth: tls.RequireAnyClientCert,
		// Each new connection must run current pairing/revocation checks.
		SessionTicketsDisabled: true,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return id.certificate()
		},
		VerifyConnection: func(state tls.ConnectionState) error {
			key, err := peerIdentity(state, x509.ExtKeyUsageClientAuth)
			if err != nil {
				return err
			}
			config, err := store.readServer()
			if err != nil {
				return errors.New("cannot read client authorization state")
			}
			if _, ok := config.Clients[key]; ok {
				return nil
			}
			// During enrollment an unpaired identity may finish TLS, but the
			// HTTP layer permits only token-authenticated POST /pair, not CONNECT.
			if config.Pending != nil && time.Now().Before(config.Pending.ExpiresAt) {
				return nil
			}
			return errors.New("client is not paired")
		},
	}
}
