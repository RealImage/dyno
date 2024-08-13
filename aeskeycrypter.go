package dyno

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"io"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"golang.org/x/crypto/pbkdf2"
)

// NewAesCrypter creates a new KeyCrypter that encrypts DynamoDB primary key attributes
// with AES GCM encryption.
// The password and salt are used to derive a 32 byte key using PBKDF2.
func NewAesCrypter(password, salt []byte) (KeyCrypter, error) {
	key := pbkdf2.Key(password, salt, 4096, 32, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &aesCryptedItem{
		mode: mode,
	}, nil
}

type aesCryptedItem struct {
	mode cipher.AEAD
}

// Encrypt encrypts a dynamodb item along with an encryption context.
func (c *aesCryptedItem) Encrypt(ctx context.Context,
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
func (c *aesCryptedItem) Decrypt(
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
