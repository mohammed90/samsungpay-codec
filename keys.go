package samsungpaycodec

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Per: https://pkg.go.dev/crypto#PrivateKey
type PrivateKey interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}

// Kid calculates the Kid of the private key
// as the base64 of the SHA-256 of the public key component
func Kid(key PrivateKey) string {
	return KidFromPublic(key.Public())
}

// KidFromPublic is the base64 of the SHA-256 of the public key
func KidFromPublic(key crypto.PublicKey) string {
	pkbs, _ := x509.MarshalPKIXPublicKey(key)
	hasher := sha256.New()
	hasher.Write(pkbs)
	return base64.StdEncoding.EncodeToString(hasher.Sum(nil))
}

// KeyProvider is a generic interface for an implementation
// fetching the private key from backing storage given `kid`.
type KeyProvider interface {
	GetKey(kid string) PrivateKey
}

// KeyAdder is a helper interface to signal the provider's
// ability to add keys.
type KeyAdder interface {
	AddKey(PrivateKey) error
}

type filesystemKeyProvider struct {
	root string

	kidFilename map[string]string
	kidMu       *sync.RWMutex
}

// Expects a directory path containing private keys formatted as PKCS8 PEM
func NewFilesystemKeyProvider(root string) (KeyProvider, error) {
	rootStat, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !rootStat.IsDir() {
		return nil, fmt.Errorf("root is not a directory: %s", root)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	kidFilename := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		bs, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			panic(err)
		}
		for block, rest := pem.Decode(bs); block != nil || len(rest) > 0; block, rest = pem.Decode(rest) {
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				panic(err)
			}
			kidFilename[Kid(key.(PrivateKey))] = filepath.Join(root, entry.Name())
		}
	}
	return &filesystemKeyProvider{root: root, kidFilename: kidFilename, kidMu: &sync.RWMutex{}}, nil
}

// GetKey returns the key stored in the file system. The keys are already indexed
// during NewFilesystemKeyProvider call. This method only hits the filesystem to open
// and read the subject file. Returns nil if none found.
func (p filesystemKeyProvider) GetKey(kid string) PrivateKey {
	p.kidMu.RLock()
	defer p.kidMu.RUnlock()
	if fname, ok := p.kidFilename[kid]; ok {
		bs, err := os.ReadFile(fname)
		if err != nil {
			return nil
		}
		for block, rest := pem.Decode(bs); block != nil || len(rest) > 0; block, rest = pem.Decode(rest) {
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				panic(err)
			}
			if key != nil && Kid(key.(PrivateKey)) == kid {
				return key.(PrivateKey)
			}
		}
	}
	return nil
}

func (p *filesystemKeyProvider) AddKey(key PrivateKey) (err error) {
	p.kidMu.Lock()
	defer p.kidMu.Unlock()

	kid := Kid(key)
	keyPath := filepath.Join(p.root, kid)
	bs, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	f, err := os.Open(keyPath)
	if err != nil {
		return err
	}
	defer func() {
		if e := f.Close(); e != nil {
			err = e
		}
	}()
	if err := pem.Encode(f, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: bs,
	}); err != nil {
		return err
	}
	p.kidFilename[kid] = keyPath
	return err
}

type memoryProvider struct {
	keys map[string]PrivateKey
	mu   *sync.RWMutex
}

// The static key provider is an in-memory key provider
func NewMemoryKeyProvider(keys ...PrivateKey) KeyProvider {
	ks := make(map[string]PrivateKey)
	for _, k := range keys {
		ks[Kid(k)] = k
	}
	return &memoryProvider{ks, &sync.RWMutex{}}
}

// GetKey returns the key from the internal memory storage. It
// returns nil if none is found for the subject 'kid'.
func (sp memoryProvider) GetKey(kid string) PrivateKey {
	sp.mu.RLock()
	defer sp.mu.RUnlock()
	return sp.keys[kid]
}

func (p *memoryProvider) AddKey(key PrivateKey) (err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys[Kid(key)] = key
	return nil
}

var _ KeyProvider = filesystemKeyProvider{}
var _ KeyAdder = &filesystemKeyProvider{}
var _ KeyProvider = memoryProvider{}
var _ KeyAdder = &memoryProvider{}
