package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Identity struct {
	key  ed25519.PrivateKey
	cert tls.Certificate
}

func DefaultKeyPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "vibemaxxer", "identity.pem")
}

func Load(path string) (*Identity, error) {
	if path == "" {
		return nil, errors.New("cannot determine the configuration directory; pass --key FILE")
	}
	key, err := readKey(path)
	if errors.Is(err, os.ErrNotExist) {
		key, err = generateKey(path)
	}
	if err != nil {
		return nil, err
	}
	return FromKey(key)
}

func FromKey(key ed25519.PrivateKey) (*Identity, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid identity key")
	}
	cert, err := selfSigned(key)
	if err != nil {
		return nil, err
	}
	return &Identity{key: key, cert: cert}, nil
}

func (id *Identity) Key() ed25519.PrivateKey { return id.key }

func readKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s: not a PEM private key", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: key must be Ed25519", path)
	}
	return key, nil
}

func generateKey(path string) (ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".identity-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(file.Name())
	if err := pem.Encode(file, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	if err := os.Link(file.Name(), path); errors.Is(err, os.ErrExist) {
		return readKey(path)
	} else if err != nil {
		return nil, err
	}
	return key, nil
}

func selfSigned(key ed25519.PrivateKey) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "vibemaxxer"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func fingerprint(pub ed25519.PublicKey) string {
	spki, _ := x509.MarshalPKIXPublicKey(pub)
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}

func (id *Identity) Fingerprint() string {
	return fingerprint(id.key.Public().(ed25519.PublicKey))
}

func ParseFingerprint(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return "", fmt.Errorf("fingerprint %q must be 64 hex characters", value)
	}
	return value, nil
}

func peerFingerprint(state tls.ConnectionState) (string, error) {
	if len(state.PeerCertificates) != 1 {
		return "", errors.New("peer must present exactly one identity certificate")
	}
	pub, ok := state.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return "", errors.New("peer identity must be Ed25519")
	}
	return fingerprint(pub), nil
}

func (id *Identity) ClientTLS(serverKey string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{id.cert},
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
		VerifyConnection: func(state tls.ConnectionState) error {
			key, err := peerFingerprint(state)
			if err != nil {
				return err
			}
			if subtle.ConstantTimeCompare([]byte(key), []byte(serverKey)) != 1 {
				return fmt.Errorf("server identity %s does not match --server-key", key)
			}
			return nil
		},
	}
}

func (id *Identity) ServerTLS(clients map[string]bool) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{id.cert},
		ClientAuth:   tls.RequireAnyClientCert,
		NextProtos:   []string{"http/1.1"},
		VerifyConnection: func(state tls.ConnectionState) error {
			key, err := peerFingerprint(state)
			if err != nil {
				return err
			}
			if !clients[key] {
				return fmt.Errorf("unknown client %s; add --client-key %s and restart", key, key)
			}
			return nil
		},
	}
}
