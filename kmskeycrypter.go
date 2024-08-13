package dyno

import (
	"context"
	"encoding/base64"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func NewKmsCrypter(kmsKeyID string, kmsClient *kms.Client) KeyCrypter {
	return &kmsCrypter{
		kmsKeyID:  kmsKeyID,
		kmsClient: kmsClient,
	}
}

// kmsCrypter is a struct that encrypts and decrypts dynamodb items with a KMS key.
type kmsCrypter struct {
	kmsKeyID  string
	kmsClient *kms.Client
}

// Encrypt encrypts a dynamodb item. If ctx contains an encryption context, it will be used
// to encrypt the item.
func (c *kmsCrypter) Encrypt(
	ctx context.Context,
	item map[string]types.AttributeValue,
) (string, error) {
	plainText, err := serialize(item)
	if err != nil {
		return "", err
	}

	in := kms.EncryptInput{
		KeyId:     &c.kmsKeyID,
		Plaintext: plainText,
	}

	if ec, ok := getEncryptionContext(ctx); ok {
		in.EncryptionContext = ec
	}

	out, err := c.kmsClient.Encrypt(ctx, &in)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(out.CiphertextBlob), nil
}

// Decrypt decrypts a dynamodb item. If ctx contains an encryption context, it will be used
// to decrypt the item. The item must have been encrypted with the same encryption context.
func (c *kmsCrypter) Decrypt(
	ctx context.Context,
	item string,
) (map[string]types.AttributeValue, error) {
	cipherText, err := base64.URLEncoding.DecodeString(item)
	if err != nil {
		return nil, err
	}

	in := kms.DecryptInput{
		KeyId:          &c.kmsKeyID,
		CiphertextBlob: cipherText,
	}

	if ec, ok := getEncryptionContext(ctx); ok {
		in.EncryptionContext = ec
	}

	out, err := c.kmsClient.Decrypt(ctx, &in)
	if err != nil {
		return nil, err
	}

	return deserialize(out.Plaintext)
}
