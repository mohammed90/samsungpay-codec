package samsungpaycodec

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

type Decryptor interface {
	Decrypt3DSData(payload []byte) (plain []byte, err error)
}

// A factory function to produce JWE decryptors compliant to the stated
// version spec and using `provider` for key retrieval
func NewJWEDecryptor(version string, provider KeyProvider) (Decryptor, error) {
	switch version {
	case "100":
		return jweRSADecryptorV100{provider: provider}, nil
	default:
		return nil, fmt.Errorf("version '%s' not supported", version)
	}
}

const (
	headerIndex = iota
	encryptionKeyIndex
	nonceIndex
	cipherTextIndex
	tagIndex
)

type jweRSADecryptorV100 struct {
	provider KeyProvider
}

func (d jweRSADecryptorV100) Decrypt3DSData(payload []byte) ([]byte, error) {
	parts := bytes.Split(payload, []byte("."))

	// ----- Begin Extract KID ---
	header := sliceForPart(parts[headerIndex])
	if _, err := base64Decoder.Decode(header, parts[headerIndex]); err != nil {
		return nil, fmt.Errorf("decoding the zeroth-part of payload: %w", err)
	}
	decodedHeader := make(map[string]string)
	if err := json.Unmarshal(header, &decodedHeader); err != nil {
		return nil, fmt.Errorf("unmarshalling header: %w", err)
	}

	key := d.provider.GetKey(decodedHeader["kid"])
	if key == nil {
		return nil, errors.New("key not Found")
	}
	// ----- End Extract KID ---

	encKey := sliceForPart(parts[encryptionKeyIndex])
	if _, err := base64Decoder.Decode(encKey, parts[encryptionKeyIndex]); err != nil {
		return nil, fmt.Errorf("decoding first-part of payload: %w", err)
	}

	iv := sliceForPart(parts[nonceIndex])
	if _, err := base64Decoder.Decode(iv, parts[nonceIndex]); err != nil {
		return nil, fmt.Errorf("decoding second-part of payload: %w", err)
	}

	cipherText := sliceForPart(parts[cipherTextIndex])
	if _, err := base64Decoder.Decode(cipherText, parts[cipherTextIndex]); err != nil {
		return nil, fmt.Errorf("decoding third-part of payload: %w", err)
	}

	tag := sliceForPart(parts[tagIndex])
	if _, err := base64Decoder.Decode(tag, parts[tagIndex]); err != nil {
		return nil, fmt.Errorf("decoding fourth-part of payload: %w", err)
	}

	plainEncKey, err := rsa.DecryptPKCS1v15(nil, key.(*rsa.PrivateKey), encKey)
	if err != nil {
		return nil, fmt.Errorf("decrypting the key: %w", err)
	}

	cipherBlock, err := aes.NewCipher(plainEncKey)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	aesgcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	plain, err := aesgcm.Open(nil, iv, append(cipherText, tag...), nil)
	if err != nil {
		return nil, fmt.Errorf("opening GCM: %w", err)
	}
	return plain, nil
}
func sliceForPart(part []byte) []byte {
	return make([]byte, base64Decoder.DecodedLen(len(part)))
}

var base64Decoder = base64.RawURLEncoding

var _ Decryptor = jweRSADecryptorV100{}
