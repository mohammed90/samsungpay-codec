package samsungpaycodec

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"
)

func mustProvider(p KeyProvider, err error) KeyProvider {
	if err != nil {
		panic(err)
	}
	return p
}

func getKey() PrivateKey {
	block, _ := pem.Decode([]byte(`-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDltx8zh9s2jYIi
DOqBJVciXKS/AxmtVnKx7Uau2UTwCAJy+WUIxvck5+9Z6U4gPx446wQNXgOwx7ah
1+JvTLfAou4mmhGDXDKFJyQ2JoldWN0S90Y5kaujzqj7tev9wveyU356/A7x/qtz
bmaplbvvTK+QBwMKB7g7m8mJ0T7hFtlZlspc+oTi+ujkN+Wth/+w/wDGqnSH50wq
QG41vGDYunCqgEYmfCPpsWIoyjaZUhbZefjEb+cUmYOmvoBRvFz8GW7Ka+yWHsnr
5Ujzg3z0wVkvGV5fOcsnc/wTDvGvhq0PE6MOQqczom3wmKjhQypF/IAF0MNimBNr
TojMP07TAgMBAAECggEBAKbETLiCVpjCHslNiyl6zEk77LZnL8rxSY72bSweu7du
eSiy+bBnkaCPaOpjP76VVAGKTITPzeoW8vWH3vFiRrxpDG+lxjURR/P2uIk/bNYB
320Xazn8ERl4vKEQL2Uol940U0xBlTAF7L5+VbWj6K4PhB0Rmhk8BXnw3V1aNUX+
immZKrBWoR+SS24NiryoPMsh2z2a+jTaxaJLc7goaMcIa6Ynic41u37uuyC3LWg6
VUWhHsAYk8oT27zK48Gk85pOmXGuNxE/ypV7rzyGGqtXHwDzCZpe08wrNR3lWhOj
PxP+8XNmn/xgx+8WvcO9eM4s05fvPjqLDROZ+/xqdQECgYEA9M0dOzP6sn7kVhsM
HM68kaJ7vSF069qi9k+6908QdUBbz7hlKFYzuN3WH8EmzVHFwOrs+NowWjXWRKym
F9MwXcM9r6UKao/0S6aeUEk3ikV2DkJmxB1rdwBNcHg7o0LwIej3TCps25s4vDCB
o+Tlyc+QiTxeNw9ukg2+8nDiaEECgYEA8DlV4lCwyH1Q1Fz40KOMb7Tg6uknlppS
YxANh6tSivkCnbmaU2J0rkz7hXjaz0Rtxr4Ucyanp81XkdXTk3uVbYo5KqkRhq0D
1DFKxudp26BWSfHn6TR4bmp0+jQH+6HhrMgs52w+oovktG48a8vjqfFGQfuMJfm6
okqdhoDdEhMCgYEA1XF6SUJ7FeMZyBHxL7T6KakYZsGjJnoNmOHPzQ489V7WLnlC
ijcPBeM2bZ2F7YOc/yZW1Gu5uQ4z8tDuSNu00iwHvvwR5vP5N3ThmHMeYAtMcgZn
gBt+tdWnr6bFqQYWRhrQdLKRE7F1eHB6uKI90QaPqXjfVPa5m9MsaEsQvYECgYEA
usNYykMBrl3/YZuGtm7w2EhANWJfrO797pakbj38Rp+iMQ4DtaBuJrUjN3nmZA5H
aqSNMZlz7znuQyuC+r6yRh+Yolofjh0lROutv0ZbPq1BaOvx6ZUprG6H055wNmp9
Ed/vSV0WtTkd7klmIEi8D3vNq67uHvgw6cwo/FFjjpECgYAvrbkP2HeqquG3yJ4Z
kEAJRHL7RiOBGlXXmSlKobH1ZvV/eaBU3bQ4pcGQ0hB6VerrQykzwFMU14zhko4s
DiLcwJ3Xu5dRDLhCpgvz/+pTAukCGLM1vHBHbYqS4a1q1VvKdvzRJl8H0YT5NyLo
W3S2/NfIFxle7Lh40YRZCY6VKw==
-----END PRIVATE KEY-----
`))
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return key.(PrivateKey)
}

func TestFilesystemKeyProviderGetKey(t *testing.T) {
	type args struct {
		kid string
	}
	tests := []struct {
		name string
		p    KeyProvider
		args args
		want PrivateKey
	}{
		{
			name: "key present in folder is found",
			p:    mustProvider(NewFilesystemKeyProvider("testdata/fs/single-key")),
			args: args{
				kid: "BOtxf/GbQW9Lca7qnmZl4FcHFiE/AdZmYXWtx9j2KVk=",
			},
			want: getKey(),
		},
		{
			name: "keys in files with multiple keys can be found",
			p:    mustProvider(NewFilesystemKeyProvider("testdata/fs/multiple-keys-in-file")),
			args: args{
				kid: "BOtxf/GbQW9Lca7qnmZl4FcHFiE/AdZmYXWtx9j2KVk=",
			},
			// this key is the second key in 'testdata/fs/multiple-keys-in-file/keys.pem'
			want: getKey(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.GetKey(tt.args.kid); !tt.want.Equal(got) {
				t.Errorf("filesystemKeyProvider.GetKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMockMastercardCard(t *testing.T) {
	nonceGetter = func() []byte {
		v, _ := hex.DecodeString("db1fb1daf085ea3231eaae0a")
		return []byte(v)
	}
	keyGetter = func() []byte {
		v, _ := hex.DecodeString("7dd874ae3b38e379d934913c298199fb")
		return []byte(v)
	}
	key := getKey().(*rsa.PrivateKey)
	jwt, pt := GetMockMastercard(key, "100", "SAR")
	d, err := NewJWEDecryptor("100", NewMemoryKeyProvider(key))
	if err != nil {
		t.Error(err)
		return
	}
	plain, err := d.Decrypt3DSData([]byte(jwt))
	if err != nil {
		t.Error(err)
		return
	}
	if string(plain) != string(pt) {
		t.Errorf("Decrypt3DSData() != GetMockMastercard(): %s != %s", plain, pt)
	}
}

func TestMockVisaCard(t *testing.T) {
	nonceGetter = func() []byte {
		v, _ := hex.DecodeString("db1fb1daf085ea3231eaae0a")
		return []byte(v)
	}
	keyGetter = func() []byte {
		v, _ := hex.DecodeString("7dd874ae3b38e379d934913c298199fb")
		return []byte(v)
	}
	key := getKey().(*rsa.PrivateKey)
	jwt, pt := GetMockVisa(key, "100", "SAR")
	d, err := NewJWEDecryptor("100", NewMemoryKeyProvider(key))
	if err != nil {
		t.Error(err)
		return
	}
	plain, err := d.Decrypt3DSData([]byte(jwt))
	if err != nil {
		t.Error(err)
		return
	}
	if string(plain) != string(pt) {
		t.Errorf("Decrypt3DSData() != GetMockVisa(): %s != %s", plain, pt)
	}
}

func TestMockAmexCard(t *testing.T) {
	nonceGetter = func() []byte {
		v, _ := hex.DecodeString("db1fb1daf085ea3231eaae0a")
		return []byte(v)
	}
	keyGetter = func() []byte {
		v, _ := hex.DecodeString("7dd874ae3b38e379d934913c298199fb")
		return []byte(v)
	}
	key := getKey().(*rsa.PrivateKey)
	jwt, pt := GetMockAmex(key, "100", "SAR")
	d, err := NewJWEDecryptor("100", NewMemoryKeyProvider(key))
	if err != nil {
		t.Error(err)
		return
	}
	plain, err := d.Decrypt3DSData([]byte(jwt))
	if err != nil {
		t.Error(err)
		return
	}
	if string(plain) != string(pt) {
		t.Errorf("Decrypt3DSData() != GetMockAmex(): %s != %s", plain, pt)
	}
}
