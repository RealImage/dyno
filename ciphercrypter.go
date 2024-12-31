package dyno

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"golang.org/x/crypto/chacha20poly1305"
)

// NewAESCrypter creates a new KeyCrypter that encrypts DynamoDB primary key attributes
// with AES GCM encryption.
// The key must be 16, 24, or 32 bytes long to select AES-128, AES-192, or AES-256.
func NewAESCrypter(key []byte) (KeyCrypter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &cipherCrypterItem{
		mode: mode,
	}, nil
}

// NewChaCha20Poly1305Crypter creates a new KeyCrypter that encrypts DynamoDB
// primary key attributes with ChaCha20-Poly1305 encryption.
// The key must be 32 bytes long.
func NewChaCha20Poly1305Crypter(key []byte) (KeyCrypter, error) {
	block, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	return &cipherCrypterItem{
		mode: block,
	}, nil
}

type cipherCrypterItem struct {
	mode cipher.AEAD
}

// Encrypt encrypts a dynamodb item along with an encryption context.
// A random nonce is used for each encryption operation.
// The nonce is prepended to the cipher text.
func (c *cipherCrypterItem) Encrypt(ctx context.Context,
	item map[string]types.AttributeValue,
) (string, error) {
	plainText, err := serialize(item)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, c.mode.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	cipherText := c.mode.Seal(nil, nonce, plainText, nil)
	cipherText = append(nonce, cipherText...)

	return base64.URLEncoding.EncodeToString(cipherText), nil
}

// Decrypt decrypts a dynamodb item along with an encryption context.
// The item must have been encrypted with the same encryption context.
func (c *cipherCrypterItem) Decrypt(
	ctx context.Context,
	itemStr string,
) (map[string]types.AttributeValue, error) {
	nonceAndCipherText, err := base64.URLEncoding.DecodeString(itemStr)
	if err != nil {
		return nil, err
	}

	plainText, err := c.mode.Open(
		nil,
		nonceAndCipherText[:c.mode.NonceSize()],
		nonceAndCipherText[c.mode.NonceSize():],
		nil,
	)
	if err != nil {
		return nil, err
	}

	return deserialize(plainText)
}
