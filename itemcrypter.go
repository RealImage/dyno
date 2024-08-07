// Package dyno provides a simple way to encrypt and decrypt dynamodb items with a KMS key.
// It is useful for passing sensitive information to a client. For example, the LastEvaluatedKey
// returned by a dynamodb query can be encrypted and passed to a client. The client can then
// pass the encrypted LastEvaluatedKey back to the server, which can decrypt it and use it
// to continue the query.
//
// Example:
//
//	// Create a new CryptedItem
//	cryptedItem := dyno.NewCryptedItem("alias/my-kms-key", kmsClient)
//
//	// Encrypt the lastEvaluatedKey
//	encryptedLastEvaluatedKey, err := cryptedItem.Encrypt(ctx, map[string]string{
//		"clientID": "1234",
//	}, lastEvaluatedKey)
//
//	// Pass the encryptedLastEvaluatedKey to the client
//
//	// Client passes the encryptedLastEvaluatedKey back to the server
//
//	// Decrypt the encryptedLastEvaluatedKey
//	lastEvaluatedKey, err := cryptedItem.Decrypt(ctx, map[string]string{
//		"clientID": "1234",
//	}, encryptedLastEvaluatedKey)
package dyno

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// ItemCrypter is an interface that encrypts and decrypts dynamodb items.
type ItemCrypter interface {
	Encrypt(ctx context.Context, item map[string]types.AttributeValue) (string, error)
	Decrypt(ctx context.Context, item string) (map[string]types.AttributeValue, error)
}

type encryptionContextKey struct{}

// WithEncryptionContext returns a new context with the given AWS KMS encryption context.
func WithEncryptionContext(ctx context.Context, ec map[string]string) context.Context {
	return context.WithValue(ctx, encryptionContextKey{}, ec)
}

func getEncryptionContext(ctx context.Context) (ec map[string]string, ok bool) {
	ec, ok = ctx.Value(encryptionContextKey{}).(map[string]string)
	return
}

func attrMapMarshalJSON(item map[string]types.AttributeValue) ([]byte, error) {
	var it map[string]any
	if err := attributevalue.UnmarshalMap(item, &it); err != nil {
		return nil, err
	}

	itJson, err := json.Marshal(it)
	if err != nil {
		return nil, err
	}

	return itJson, nil
}

func attrMapUnmarshalJSON(itJson []byte) (map[string]types.AttributeValue, error) {
	var it map[string]any
	if err := json.Unmarshal(itJson, &it); err != nil {
		return nil, err
	}

	return attributevalue.MarshalMap(it)
}
