package samsungpaycodec

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"testing"
)

func Test_JWERSADecryptorV100_Decrypt3DSData(t *testing.T) {
	const testVersion = "100"
	type args struct {
		payload []byte
	}
	tests := []struct {
		name    string
		d       Decryptor
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Samsung Pay JWE of Visa card is successfully decoded with the designated private key",
			d:    must(NewJWEDecryptor(testVersion, NewMemoryKeyProvider(getRSAKey()))),
			args: args{
				payload: []byte("eyJhbGciOiJSU0ExXzUiLCJraWQiOiJCT3R4Zi9HYlFXOUxjYTdxbm1abDRGY0hGaUUvQWRabVlYV3R4OWoyS1ZrPSIsInR5cCI6IkpPU0UiLCJjaGFubmVsU2VjdXJpdHlDb250ZXh0IjoiUlNBX1BLSSIsImVuYyI6IkExMjhHQ00ifQ.fCkzRPNpcZtNMv0gsfBsZm_l_-4lVTrN9iI4UAmqmZ_FzsRWASwMkd54kPDZetTjsK1Ni4HG307qRDDBrSLty2RBvWBWRU5ywyYLDM2ee8vjBetEsDA8RQavXbZGxMLqOsaMk2D8nYV4iz91m3-DHCNbBIuth9BZQwpBFp77ducCT7v1MSpIuExhmuJurayL0XbsN2kSdBl0cw2tpzCOvMF9cX4VQc4a0ewA5PVWGDeC0wia92DctoIo_N5ZqamSctUloraO64BbKuWhwGbhGaRFx4U9mkSuJ2lLPNRIBwvq-vDXKA1cmdqs-iSRc40e-hVdK655TkDNk9xcCyN_aA.2x-x2vCF6jIx6q4K.EUtBZyTbI98gg0WREQAbJAoL-oQ6b9yN9uZRmv5lX8uDcj9NHADRTMP-Qhey32_kMtVDV2kGRTs9xmlbiNWQF46Wj8zpAigYrwb5AfYH7-OXBv-9dKKf49Gp2_07uKywTBmnOpfkf1FKKCRlzlnRQKVREwXxvft3LSRP87KGZc8jTn3kMcE-vdSJG2OK62yMwEGJ2cHV7PSl-uERqYs3BnDpuXmx-Ly84k9qXp1wpo-ArKYLqznQ_ubA.bFK6fe6IQprZZ1xErKxCvg"),
			},
			want:    []byte(`{"amount":"106000","cryptogram":"AwAABCQACCDLHvYBtQ9EgUUQYaA=","currency_code":"USD","eci_indicator":"05","tokenPanExpiration":"1127","utc":"1700557639934","tokenPAN":"4558386640000312"}`),
			wantErr: false,
		},
		{
			name: "Samsung Pay JWE of MC card is successfully decoded with the designated private key",
			d:    must(NewJWEDecryptor(testVersion, NewMemoryKeyProvider(getRSAKey()))),
			args: args{
				payload: []byte("eyJhbGciOiJSU0ExXzUiLCJraWQiOiJCT3R4Zi9HYlFXOUxjYTdxbm1abDRGY0hGaUUvQWRabVlYV3R4OWoyS1ZrPSIsInR5cCI6IkpPU0UiLCJjaGFubmVsU2VjdXJpdHlDb250ZXh0IjoiUlNBX1BLSSIsImVuYyI6IkExMjhHQ00ifQ.oPMwMRdoM4aVonoTUXVouxqV-fuk9i7qwNDbOLrAI8z2Enn9AvwkJriBzitdlEXi91IyCcBqvoI-la3VHd1zHd257XJbIZWViLkYRh-IGmEXjM6C4XFRuS47PVal-bs98lSZW2Xsf3rR51Vjb_mKLDPLV5OzaMdajw1FL_GTyohedqmTGtFgaoIwo8DHa1Q9Iu4MWmnJWEwUdzUfWVcl0SpuqtGLbpJw4Zg6WxGxP8gx7DkTyqiVoiomJp6BtaZppInENT_q1uMuM_oukQeb_NneCTbnYRcD1hOaYcbZonztuE_Ty9i7iMztPH7LEd5prI990J2tdS9ROlOivD_d6A.qgCXv9WXbY-FDoTd.TNhZ_ImT-OPs-VH5A0VYny9XKvE9nANaWIPFvvIOQjCaBZ3gbpWpWPrfotnhPjw1h2-54PmN8U9NYMwSelEWxd3-Z5tuTlwT94NXw_VsIZMQ4Dm3feCFtq4xLEF3wuiaVGhVKKLtfVkLD-QPKQuaTWrJuUgYdjKYPdLjWZBX-wl9S72Qw7QQISju_o2hYz7hors-dDa4rGmt7vI7Y8O1DlO4ozdA3BD3jh5uV4e5vh4sl6avmSckjC8.UDU6UR0n7iuDYNPxgdQXzA"),
			},
			want:    []byte(`{"amount":"106000","currency_code":"USD","utc":"1700480649483","eci_indicator":"5","tokenPAN":"5214150084269830","tokenPanExpiration":"1126","cryptogram":"AILsL+OF38dxAAQSUy+FAoACFA=="}`),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.d.Decrypt3DSData(tt.args.payload)
			if (err != nil) != tt.wantErr {
				t.Errorf("jweRSADecryptorV100.Decrypt3DSData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("jweRSADecryptorV100.Decrypt3DSData() = %s, want %s", got, tt.want)
			}
		})
	}
}

func must(d Decryptor, err error) Decryptor {
	if err != nil {
		panic(err)
	}
	return d
}

func getRSAKey() *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(pkcs8key))
	key, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	return key.(*rsa.PrivateKey)
}

const pkcs8key = `-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----`
