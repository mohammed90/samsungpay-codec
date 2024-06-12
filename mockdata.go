package samsungpaycodec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

type paymentCredential struct {
	Amount             string `json:"amount"`
	CurrencyCode       string `json:"currency_code"`
	Utc                string `json:"utc"`
	EciIndicator       string `json:"eci_indicator"`
	TokenPAN           string `json:"tokenPAN"`
	TokenPanExpiration string `json:"tokenPanExpiration"`
	Cryptogram         string `json:"cryptogram"`
}

type jweHeader struct {
	Alg                    string `json:"alg"`
	Kid                    string `json:"kid"`
	Typ                    string `json:"typ"`
	ChannelSecurityContext string `json:"channelSecurityContext"`
	Enc                    string `json:"enc"`
}

type mpgsSPayCard struct {
	dpan        string
	expiryMonth string
	expiryYear  string
	cryptogram  string
}

const (
	testCryptogram = "AAAAAAAALJI6DbfqRzUcwAC6gAAGhgEDoLABAAhAgAABAAAAMlkUxA=="
	tagLength      = 16
)

var (
	mastercardTestCard mpgsSPayCard = mpgsSPayCard{
		dpan:        "5123456789012346",
		expiryMonth: "01",
		expiryYear:  "39",
		cryptogram:  testCryptogram,
	}
	visaTestCard = mpgsSPayCard{
		dpan:        "340353278080900",
		expiryMonth: "01",
		expiryYear:  "39",
		cryptogram:  testCryptogram,
	}
	amexTestCard = mpgsSPayCard{
		dpan:        "4440000009900010",
		expiryMonth: "01",
		expiryYear:  "39",
		cryptogram:  testCryptogram,
	}
)

var nonceGetter = func() []byte {
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	return nonce
}
var keyGetter = func() []byte {
	encryptionKey := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, encryptionKey); err != nil {
		panic(err.Error())
	}
	return encryptionKey
}

// Produces a JWE and plaintext of a Mastercard test DPAN. Uses the test card listed on MPGS documentation:
// https://ap-gateway.mastercard.com/api/documentation/integrationGuidelines/supportedFeatures/pickPaymentMethod/devicePayments/SamsungPay.html?locale=en_US
func GetMockMastercard(key *rsa.PrivateKey, amount, currency string) (jwe string, plaintext []byte) {
	header := jweHeader{
		Alg:                    "RSA1_5",
		Kid:                    Kid(key),
		Typ:                    "JOSE",
		ChannelSecurityContext: "RSA_PKI",
		Enc:                    "A128GCM",
	}
	headerbs, _ := json.Marshal(header)

	pc := paymentCredential{
		Amount:             amount,
		CurrencyCode:       currency,
		Utc:                fmt.Sprintf("%d", time.Now().UnixMilli()),
		EciIndicator:       "02",
		TokenPAN:           mastercardTestCard.dpan,
		TokenPanExpiration: mastercardTestCard.expiryMonth + mastercardTestCard.expiryYear,
		Cryptogram:         testCryptogram,
	}
	plaintext, _ = json.Marshal(pc)

	encryptionKey := keyGetter()
	nonce := nonceGetter()

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		panic(err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	tag := ciphertext[len(ciphertext)-tagLength:]
	ciphertext = ciphertext[:len(ciphertext)-tagLength]

	encryptedKey, _ := rsa.EncryptPKCS1v15(rand.Reader, key.Public().(*rsa.PublicKey), encryptionKey)

	headerPart := base64Decoder.EncodeToString(headerbs)
	keyPart := base64Decoder.EncodeToString(encryptedKey)
	noncePart := base64Decoder.EncodeToString(nonce)
	payloadPart := base64Decoder.EncodeToString(ciphertext)
	tagPart := base64Decoder.EncodeToString(tag)

	return strings.Join([]string{
		headerPart,
		keyPart,
		noncePart,
		payloadPart,
		tagPart,
	}, "."), plaintext
}

// Produces a JWE and plaintext of a Visa test DPAN. Uses the test card listed on MPGS documentation:
// https://ap-gateway.mastercard.com/api/documentation/integrationGuidelines/supportedFeatures/pickPaymentMethod/devicePayments/SamsungPay.html?locale=en_US
func GetMockVisa(key *rsa.PrivateKey, amount, currency string) (jwe string, plaintext []byte) {
	header := jweHeader{
		Alg:                    "RSA1_5",
		Kid:                    Kid(key),
		Typ:                    "JOSE",
		ChannelSecurityContext: "RSA_PKI",
		Enc:                    "A128GCM",
	}
	headerbs, _ := json.Marshal(header)

	pc := paymentCredential{
		Amount:             amount,
		CurrencyCode:       currency,
		Utc:                fmt.Sprintf("%d", time.Now().UnixMilli()),
		EciIndicator:       "02",
		TokenPAN:           visaTestCard.dpan,
		TokenPanExpiration: visaTestCard.expiryMonth + visaTestCard.expiryYear,
		Cryptogram:         testCryptogram,
	}
	plaintext, _ = json.Marshal(pc)

	encryptionKey := keyGetter()
	nonce := nonceGetter()

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		panic(err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	tag := ciphertext[len(ciphertext)-tagLength:]
	ciphertext = ciphertext[:len(ciphertext)-tagLength]

	encryptedKey, _ := rsa.EncryptPKCS1v15(rand.Reader, key.Public().(*rsa.PublicKey), encryptionKey)

	headerPart := base64Decoder.EncodeToString(headerbs)
	keyPart := base64Decoder.EncodeToString(encryptedKey)
	noncePart := base64Decoder.EncodeToString(nonce)
	payloadPart := base64Decoder.EncodeToString(ciphertext)
	tagPart := base64Decoder.EncodeToString(tag)

	return strings.Join([]string{
		headerPart,
		keyPart,
		noncePart,
		payloadPart,
		tagPart,
	}, "."), plaintext
}

// Produces a JWE and plaintext of an American Express test DPAN. Uses the test card listed on MPGS documentation:
// https://ap-gateway.mastercard.com/api/documentation/integrationGuidelines/supportedFeatures/pickPaymentMethod/devicePayments/SamsungPay.html?locale=en_US
func GetMockAmex(key *rsa.PrivateKey, amount, currency string) (jwe string, plaintext []byte) {
	header := jweHeader{
		Alg:                    "RSA1_5",
		Kid:                    Kid(key),
		Typ:                    "JOSE",
		ChannelSecurityContext: "RSA_PKI",
		Enc:                    "A128GCM",
	}
	headerbs, _ := json.Marshal(header)

	pc := paymentCredential{
		Amount:             amount,
		CurrencyCode:       currency,
		Utc:                fmt.Sprintf("%d", time.Now().UnixMilli()),
		EciIndicator:       "02",
		TokenPAN:           amexTestCard.dpan,
		TokenPanExpiration: amexTestCard.expiryMonth + amexTestCard.expiryYear,
		Cryptogram:         testCryptogram,
	}
	plaintext, _ = json.Marshal(pc)

	encryptionKey := keyGetter()
	nonce := nonceGetter()

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		panic(err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	tag := ciphertext[len(ciphertext)-tagLength:]
	ciphertext = ciphertext[:len(ciphertext)-tagLength]

	encryptedKey, _ := rsa.EncryptPKCS1v15(rand.Reader, key.Public().(*rsa.PublicKey), encryptionKey)

	headerPart := base64Decoder.EncodeToString(headerbs)
	keyPart := base64Decoder.EncodeToString(encryptedKey)
	noncePart := base64Decoder.EncodeToString(nonce)
	payloadPart := base64Decoder.EncodeToString(ciphertext)
	tagPart := base64Decoder.EncodeToString(tag)

	return strings.Join([]string{
		headerPart,
		keyPart,
		noncePart,
		payloadPart,
		tagPart,
	}, "."), plaintext
}
