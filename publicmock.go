package samsungpaycodec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Produces a JWE and plaintext of a Mastercard test DPAN. Uses the test card listed on MPGS documentation:
// https://ap-gateway.mastercard.com/api/documentation/integrationGuidelines/supportedFeatures/pickPaymentMethod/devicePayments/SamsungPay.html?locale=en_US
func GetMockMastercardWithPublicKey(key *rsa.PublicKey, amount, currency string) (jwe string, plaintext []byte) {
	header := jweHeader{
		Alg:                    "RSA1_5",
		Kid:                    KidFromPublic(key),
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

	encryptedKey, _ := rsa.EncryptPKCS1v15(rand.Reader, key, encryptionKey)

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
func GetMockVisaWithPublicKey(key *rsa.PublicKey, amount, currency string) (jwe string, plaintext []byte) {
	header := jweHeader{
		Alg:                    "RSA1_5",
		Kid:                    KidFromPublic(key),
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

	encryptedKey, _ := rsa.EncryptPKCS1v15(rand.Reader, key, encryptionKey)

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
func GetMockAmexWithPublicKey(key *rsa.PublicKey, amount, currency string) (jwe string, plaintext []byte) {
	header := jweHeader{
		Alg:                    "RSA1_5",
		Kid:                    KidFromPublic(key),
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

	encryptedKey, _ := rsa.EncryptPKCS1v15(rand.Reader, key, encryptionKey)

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
