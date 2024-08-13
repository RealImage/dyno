package dyno

import (
	"context"
	"encoding/base64"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// NewKmsCrypter returns a KeyCrypter that encrypts and decrypts dynamodb primary key
// attributevalues using AWS KMS.
// The KMS key ID is the ARN of the KMS key used to encrypt and decrypt the items.
// The KMS client is used to call the KMS API. If nil, a new client will be created.
func NewKmsCrypter(kmsKeyID string, kmsClient *kms.Client) KeyCrypter {
	if kmsClient == nil {
		kmsClient = kms.New(kms.Options{})
	}

	return &kmsCrypter{
		kmsKeyID:  kmsKeyID,
		kmsClient: kmsClient,
	}
}

type kmsCrypter struct {
	kmsKeyID  string
	kmsClient *kms.Client
}

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
