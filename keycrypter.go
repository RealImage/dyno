// Package dyno provides a simple way to encrypt and decrypt dynamodb items with a KMS key.
// It is useful for passing sensitive information to a client. For example, the LastEvaluatedKey
// returned by a dynamodb query can be encrypted and passed to a client. The client can then
// pass the encrypted LastEvaluatedKey back to the server, which can decrypt it and use it
// to continue the query.
//
// Example:
//
//	// Create a new AesCrypter
//	crypter := dyno.NewAesCrypter([]byte("encryption-password"), []byte("salt"))
//
//	// Encrypt the lastEvaluatedKey
//	encryptedLastEvaluatedKey, err := crypter.Encrypt(ctx, map[string]string{
//		"clientID": "1234",
//	}, lastEvaluatedKey)
//
//	// Pass the encryptedLastEvaluatedKey to the client in the response
//
//	// Client passes the encryptedLastEvaluatedKey back to the server in the next request
//
//	// Decrypt the encryptedLastEvaluatedKey
//	lastEvaluatedKey, err := crypter.Decrypt(ctx, map[string]string{
//		"clientID": "1234",
//	}, encryptedLastEvaluatedKey)
package dyno

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// KeyCrypter is an interface that encrypts and decrypts DynamoDB primary key attribute values.
type KeyCrypter interface {
	// Encrypt encrypts a DynamoDB primary key item along with an encryption context.
	Encrypt(ctx context.Context, item map[string]types.AttributeValue) (string, error)
	// Decrypt decrypts a DynamoDB primary key item.
	// If the item was encrypted with an encryption context,
	// the same context must be provided to decrypt the item.
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

func serialize(input map[string]types.AttributeValue) ([]byte, error) {
	for _, v := range input {
		switch v.(type) {
		case *types.AttributeValueMemberS, *types.AttributeValueMemberB, *types.AttributeValueMemberN:
			continue
		default:
			return nil, fmt.Errorf("unsupported type: %T", v)
		}
	}

	var jsonMap map[string]any
	if err := attributevalue.UnmarshalMap(input, &jsonMap); err != nil {
		return nil, err
	}

	return json.Marshal(jsonMap)
}

func deserialize(input []byte) (map[string]types.AttributeValue, error) {
	var jsonMap map[string]any
	if err := json.Unmarshal(input, &jsonMap); err != nil {
		return nil, err
	}

	output, err := attributevalue.MarshalMap(jsonMap)
	if err != nil {
		return nil, err
	}

	// Convert hex strings back to byte slices
	for k, v := range output {
		if s, ok := v.(*types.AttributeValueMemberS); ok {
			if val, err := base64.StdEncoding.DecodeString(s.Value); err == nil {
				output[k] = &types.AttributeValueMemberB{Value: val}
			}
		}
	}

	return output, nil
}
