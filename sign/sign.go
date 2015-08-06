package sign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

// 通过Alipay的商户私钥进行签名
func AlipayPrivateKeySign(privateKeyStr string, content []byte) (sign string, err error) {
	der, err := base64.StdEncoding.DecodeString(privateKeyStr)
	if err != nil {
		return
	}

	privatekey, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return
	}

	hashType := crypto.SHA1
	if !hashType.Available() {
		err = errors.New("unsupport sha1")
		return
	}

	h := hashType.New()
	h.Write(content)
	digest := h.Sum(nil)

	_privatekey := privatekey.(*rsa.PrivateKey)

	signature, err := rsa.SignPKCS1v15(rand.Reader, _privatekey, crypto.SHA1, digest)
	if err != nil {
		return
	}

	sign = base64.StdEncoding.EncodeToString(signature)
	return
}
