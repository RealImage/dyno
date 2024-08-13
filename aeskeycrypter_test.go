package dyno

import (
	"context"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

var testCases = []struct {
	name string
	item map[string]types.AttributeValue
	err  bool
}{
	{
		name: "string",
		item: map[string]types.AttributeValue{
			"key": &types.AttributeValueMemberS{Value: "value"},
		},
	},
	{
		name: "number",
		item: map[string]types.AttributeValue{
			"key": &types.AttributeValueMemberN{Value: "123"},
		},
	},
	{
		name: "binary",
		item: map[string]types.AttributeValue{
			"key": &types.AttributeValueMemberB{Value: []byte("value")},
		},
	},
	{
		name: "bool",
		item: map[string]types.AttributeValue{
			"key": &types.AttributeValueMemberBOOL{Value: true},
		},
		err: true,
	},
	{
		name: "null",
		item: map[string]types.AttributeValue{
			"key": &types.AttributeValueMemberNULL{Value: true},
		},
		err: true,
	},
	{
		name: "list",
		item: map[string]types.AttributeValue{
			"key": &types.AttributeValueMemberL{
				Value: []types.AttributeValue{
					&types.AttributeValueMemberS{Value: "value"},
					&types.AttributeValueMemberN{Value: "123"},
					&types.AttributeValueMemberB{Value: []byte("value")},
					&types.AttributeValueMemberBOOL{Value: true},
					&types.AttributeValueMemberNULL{Value: true},
				},
			},
		},
		err: true,
	},
	{
		name: "map",
		item: map[string]types.AttributeValue{
			"key": &types.AttributeValueMemberM{
				Value: map[string]types.AttributeValue{
					"key": &types.AttributeValueMemberS{Value: "value"},
				},
			},
		},
		err: true,
	},
	{
		name: "binarySet",
		item: map[string]types.AttributeValue{
			"key": &types.AttributeValueMemberBS{
				Value: [][]byte{
					[]byte("value"),
				},
			},
		},
		err: true,
	},
}

func TestAesCrypter(t *testing.T) {
	password := []byte("password")
	salt := []byte("saltsalt")

	ic, err := NewAesCrypter(password, salt)
	if err != nil {
		t.Fatalf("NewAesItemCrypter() error = %v, want nil", err)
	}

	if ic == nil {
		t.Fatalf("NewAesItemCrypter() = nil, want not nil")
	}

	for _, tc := range testCases {
		t.Run("EncryptDecrypt_"+tc.name, func(t *testing.T) {
			cipherText, err := ic.Encrypt(context.Background(), tc.item)

			if tc.err {
				if err == nil {
					t.Fatalf("Encrypt() error = nil, want error")
				}

				// OK
				return
			}

			if err != nil {
				t.Fatalf("Encrypt() error = %v, want nil", err)
			}

			plainText, err := ic.Decrypt(context.Background(), cipherText)
			if err != nil {
				t.Fatalf("Decrypt() error = %v, want nil", err)
			}

			if !reflect.DeepEqual(tc.item, plainText) {
				t.Fatalf("Decrypt() = %v, want %v", plainText, tc.item)
			}
		})
	}
}
