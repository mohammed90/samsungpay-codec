package samsungpaycodec

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"
)

func gePublicKey() *rsa.PublicKey {
	block, _ := pem.Decode([]byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIC+DCCAeACAQAwgZQxCzAJBgNVBAYTAlNBMQwwCgYDVQQIDANSVUgxDDAKBgNV
BAcMA1JVSDEPMA0GA1UECgwGZmx5bmFzMQswCQYDVQQLDAJGTDEoMCYGA1UEAwwf
Y29tLmZseW5hc21vYmlsZS5zYW1zdW5ncGF5dGVzdDEhMB8GCSqGSIb3DQEJARYS
amdheWFtb0BmbHluYXMuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEArBoR08PQcIDhM965osC/NFIT97NDfbrw8SQEyAp7svDdjnTv4BqXJViEMJf7
wK3mEfNV729u31keC40rnjIaAMB8672Dmx0CLAjT/LWqmh2sPkcNGsWSn4oU0VcE
I0rRsO8QpnUTDC7xRzHWY0WZYqVbScRZDrIidNKuToZmZaq5C1sRU6IuD9guSHTy
CsRhBLZe/axBOohu57Vgo4jXZ5I+v4qn73qSqcZKp1P0uSl6gQmjz1VP545ODV3t
n/hgT7Yp8r+m76j1IrnkGuswR7m7w/i2Xx5ZB5bqBwwUsOc2plnSkQYudu+RogJD
M10mWJxvkUcBk93qdRj5q0KexQIDAQABoB4wHAYJKoZIhvcNAQkHMQ8MDUZseW5h
c0AyMDI0KiowDQYJKoZIhvcNAQELBQADggEBAG0CUkqucPe3YNpzV6w61OHj+5qK
svMdeEsnRsMwSJA5arvXCBkcQ00MZ6ZMus/A47q8RZMH2UNhjxtT/cI2/zCadTlF
ZKiBAAuP0hqC3+G08LkXja5SCQEuIu6fs6njURabtGDCt1yfY9VHdghJNTqk5XI4
aoBKAjybL37oW2IeLru4JPPAl+1QHkf+knyFZhhjn45H3IcJZ2vWA4SBbFrq/a3u
ZFKz95y9bdblb+IohVwVgMe9ATc7lhw9/jrMJBdHCKzTgP9TpZhRaFTpJ3Y453Aj
Ot0oGYUYdShaMK6IAcidgHm2Y3xXhkiU+R1H5ru+4EUB95ez5w4k/TpBmxE=
-----END CERTIFICATE REQUEST-----

`))
	creq, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		panic(err)
	}
	return creq.PublicKey.(*rsa.PublicKey)
}

func TestMockMastercardCardWithPublicKey(t *testing.T) {
	nonceGetter = func() []byte {
		v, _ := hex.DecodeString("db1fb1daf085ea3231eaae0a")
		return []byte(v)
	}
	keyGetter = func() []byte {
		v, _ := hex.DecodeString("7dd874ae3b38e379d934913c298199fb")
		return []byte(v)
	}
	key := gePublicKey()
	jwt, pt := GetMockMastercardWithPublicKey(key, "100", "SAR")
	t.Logf("JWT: %s\n", jwt)
	t.Logf("Plaintext: %s\n", pt)
}

func TestMockVisaCardWithPublicKey(t *testing.T) {
	nonceGetter = func() []byte {
		v, _ := hex.DecodeString("db1fb1daf085ea3231eaae0a")
		return []byte(v)
	}
	keyGetter = func() []byte {
		v, _ := hex.DecodeString("7dd874ae3b38e379d934913c298199fb")
		return []byte(v)
	}
	key := gePublicKey()
	jwt, pt := GetMockVisaWithPublicKey(key, "100", "SAR")
	t.Logf("JWT: %s\n", jwt)
	t.Logf("Plaintext: %s\n", pt)
}

func TestMockAmexCardWithPublicKey(t *testing.T) {
	nonceGetter = func() []byte {
		v, _ := hex.DecodeString("db1fb1daf085ea3231eaae0a")
		return []byte(v)
	}
	keyGetter = func() []byte {
		v, _ := hex.DecodeString("7dd874ae3b38e379d934913c298199fb")
		return []byte(v)
	}
	key := gePublicKey()
	jwt, pt := GetMockAmexWithPublicKey(key, "100", "SAR")
	t.Logf("JWT: %s\n", jwt)
	t.Logf("Plaintext: %s\n", pt)
}
