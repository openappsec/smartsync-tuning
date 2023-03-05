package s3repository

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"

	"openappsec.io/errors"
)

const (
	s3EncryptionBase = "AES_ENCRYPTION"
	s3EncryptionKey  = s3EncryptionBase + "_KEY"
	s3EncryptionIV   = s3EncryptionBase + "_IV"
	s3Obfuscate      = "ENCRYPTION_OBFUSCATE"
)

type encryptor struct {
	obfuscationKey []byte
	iv             []byte
	block          cipher.Block
}

func newEncryptor(conf Configuration) (*encryptor, error) {
	var adapter encryptor
	keyStr, err := conf.GetString(s3EncryptionKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get encryption key")
	}
	key := []byte(keyStr)

	ivStr, err := conf.GetString(s3EncryptionIV)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get encryption iv")
	}
	adapter.iv = []byte(ivStr)

	obf, err := conf.GetString(s3Obfuscate)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get encryption obfuscation key")
	}
	adapter.obfuscationKey = []byte(obf)

	adapter.block, err = aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create AES cipher")
	}
	return &adapter, nil
}

func (e *encryptor) decrypt(src []byte) ([]byte, error) {
	srcB64Dec := make([]byte, len(src))
	n, err := base64.StdEncoding.Decode(srcB64Dec, src)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode base 64")
	}
	srcB64Dec = srcB64Dec[:n]
	srcB64Dec = e.obfuscateXor(srcB64Dec)

	srcToDec := srcB64Dec[:len(srcB64Dec)-1]
	dec := make([]byte, len(srcToDec))
	padding := srcB64Dec[len(srcB64Dec)-1]

	decryptor := cipher.NewCBCDecrypter(e.block, e.iv)
	decryptor.CryptBlocks(dec, srcToDec)

	return dec[:len(dec)-int(padding)], nil
}

func (e *encryptor) encrypt(src []byte) []byte {
	//size_t encrypt_size = ((input.size() + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	encryptorBlockMode := cipher.NewCBCEncrypter(e.block, e.iv)
	encryptSize := ((len(src) + encryptorBlockMode.BlockSize()) / encryptorBlockMode.BlockSize()) * encryptorBlockMode.BlockSize()

	srcB64Enc := make([]byte, encryptSize+1)
	srcB64Enc[encryptSize] = byte(encryptSize - len(src))
	srcWithPadding := make([]byte, encryptSize)
	copy(srcWithPadding, src)
	encryptorBlockMode.CryptBlocks(srcB64Enc, srcWithPadding)

	obfuscatedSrc := e.obfuscateXor(srcB64Enc)

	enc := bytes.Buffer{}
	encoder := base64.NewEncoder(base64.StdEncoding, &enc)
	encoder.Write(obfuscatedSrc)
	encoder.Close()

	return enc.Bytes()
}

func (e *encryptor) obfuscateXor(src []byte) []byte {
	for i := range src {
		src[i] ^= e.obfuscationKey[i%len(e.obfuscationKey)]
	}
	return src
}
