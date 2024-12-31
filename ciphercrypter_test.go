package dyno

import (
	"context"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func TestCipherCrypterBadKeyLengths(t *testing.T) {
	t.Run("AES", func(t *testing.T) {
		if _, err := NewAESCrypter([]byte("password")); err == nil {
			t.Error("NewAESCrypter() error = nil, want error")
		}
	})

	t.Run("ChaCha20Poly1305", func(t *testing.T) {
		if _, err := NewChaCha20Poly1305Crypter([]byte("password")); err == nil {
			t.Error("NewChaCha20Poly1305Crypter() error = nil, want error")
		}
	})
}

type encryptDecryptTest struct {
	name string
	item map[string]types.AttributeValue
	err  bool
}

var testCases = []encryptDecryptTest{
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

func TestCipherCrypter(t *testing.T) {
	key := []byte("passwordpasswordpasswordpassword")

	t.Run("AES", func(t *testing.T) {
		ic, err := NewAESCrypter(key)
		if err != nil {
			t.Fatalf("NewAesItemCrypter() error = %v, want nil", err)
		}
		if ic == nil {
			t.Fatalf("NewAESCrypter() = nil, want not nil")
		}
		t.Run("EncryptDecrypt", func(t *testing.T) {
			encryptDecryptHelper(t, ic, testCases)
		})
	})

	t.Run("ChaCha20Poly1305", func(t *testing.T) {
		ic, err := NewChaCha20Poly1305Crypter(key)
		if err != nil {
			t.Fatalf("NewChaCha20Poly1305Crypter() error = %v, want nil", err)
		}
		if ic == nil {
			t.Fatalf("NewChaCha20Poly1305Crypter() = nil, want not nil")
		}
		t.Run("EncryptDecrypt", func(t *testing.T) {
			encryptDecryptHelper(t, ic, testCases)
		})
	})
}

func encryptDecryptHelper(t *testing.T, ic KeyCrypter, tcs []encryptDecryptTest) {
	t.Helper()

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {

			cipherText, err := ic.Encrypt(context.Background(), tc.item)

			if tc.err {
				if err == nil {
					t.Fatal("Encrypt() error = nil, want error")
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
