package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// State is private to the current Unix user. flock serializes CLI commands and
// the running server; atomic replacement prevents readers seeing partial JSON.
type stateStore struct{ dir string }

type clientRecord struct {
	Name    string    `json:"name"`
	AddedAt time.Time `json:"added_at"`
}

type pendingInvitation struct {
	TokenHash string    `json:"token_hash"`
	ExpiresAt time.Time `json:"expires_at"`
}

type serverState struct {
	Version int                     `json:"version"`
	Address string                  `json:"address"`
	Clients map[string]clientRecord `json:"clients"`
	Pending *pendingInvitation      `json:"pending,omitempty"`
}

type bridgeState struct {
	Version   int    `json:"version"`
	Address   string `json:"address"`
	ServerKey string `json:"server_key"`
}

func defaultStateDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "" // Commands report a useful error unless -state-dir is supplied.
	}
	return filepath.Join(dir, "vibemaxxer")
}

func openStore(dir string) (*stateStore, error) {
	if dir == "" {
		return nil, errors.New("cannot determine configuration directory; set -state-dir")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("state directory %q must be a real directory accessible only to its owner (chmod 700)", dir)
	}
	return &stateStore{dir: dir}, nil
}

func (s *stateStore) locked(fn func() error) error {
	file, err := os.OpenFile(filepath.Join(s.dir, ".lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("state lock must be a private regular file")
	}
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		return err
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	return fn()
}

func (s *stateStore) read(name string, value any) error {
	data, err := s.readPrivate(name)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, value); err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	return nil
}

func (s *stateStore) readPrivate(name string) ([]byte, error) {
	file, err := os.OpenFile(filepath.Join(s.dir, name), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("%s must be a private regular file (chmod 600)", name)
	}
	const maxSize = 1 << 20
	data, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err == nil && len(data) > maxSize {
		err = fmt.Errorf("%s is too large", name)
	}
	return data, err
}

func (s *stateStore) write(name string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return s.writePrivate(name, append(data, '\n'))
}

func (s *stateStore) writePrivate(name string, data []byte) error {
	file, err := os.CreateTemp(s.dir, ".tmp-*") // 0600, including before rename.
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), filepath.Join(s.dir, name)); err != nil {
		return err
	}
	dir, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (s *stateStore) loadServer() (serverState, error) {
	var state serverState
	if err := s.read("server.json", &state); err != nil {
		return state, err
	}
	if state.Version != 1 || state.Clients == nil {
		return state, errors.New("invalid or unsupported server state")
	}
	return state, nil
}

func (s *stateStore) initServer(address string) error {
	return s.locked(func() error {
		state, err := s.loadServer()
		if errors.Is(err, os.ErrNotExist) {
			state = serverState{Version: 1, Clients: make(map[string]clientRecord)}
		} else if err != nil {
			return err
		}
		state.Address = address
		// An invitation for an old endpoint must not remain usable.
		state.Pending = nil
		return s.write("server.json", state)
	})
}

func (s *stateStore) readServer() (state serverState, err error) {
	err = s.locked(func() error {
		state, err = s.loadServer()
		return err
	})
	return
}

func (s *stateStore) updateServer(fn func(*serverState) error) error {
	return s.locked(func() error {
		state, err := s.loadServer()
		if err != nil {
			return err
		}
		if err := fn(&state); err != nil {
			return err
		}
		return s.write("server.json", state)
	})
}

func (s *stateStore) readBridge() (state bridgeState, err error) {
	err = s.locked(func() error {
		if err := s.read("bridge.json", &state); err != nil {
			return err
		}
		if state.Version != 1 || !validFingerprint(state.ServerKey) {
			return errors.New("invalid or unsupported bridge state")
		}
		return validEndpoint(state.Address)
	})
	return
}

func validFingerprint(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

// A missing key is only generated for a new state directory. Losing an identity
// must not silently replace it while preserving old pairing configuration.
func (s *stateStore) identityKey() (key ed25519.PrivateKey, err error) {
	err = s.locked(func() error {
		data, err := s.readPrivate("identity.pem")
		if err == nil {
			block, rest := pem.Decode(data)
			if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
				return errors.New("invalid identity key")
			}
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return err
			}
			var ok bool
			key, ok = parsed.(ed25519.PrivateKey)
			if !ok {
				return errors.New("identity key must be Ed25519")
			}
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		for _, name := range []string{"server.json", "bridge.json"} {
			if _, err := os.Lstat(filepath.Join(s.dir, name)); !errors.Is(err, os.ErrNotExist) {
				return errors.New("identity key is missing from existing state; restore it or use a new state directory and re-pair")
			}
		}
		_, key, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		return s.writePrivate("identity.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	})
	return
}
