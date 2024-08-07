package dyno

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func TestAesItemCrypter(t *testing.T) {
	password := []byte("password")
	salt := []byte("saltsalt")

	ic, err := NewAesItemCrypter(password, salt)
	if err != nil {
		t.Fatalf("NewAesItemCrypter() error = %v, want nil", err)
	}

	if ic == nil {
		t.Fatalf("NewAesItemCrypter() = nil, want not nil")
	}

	item := map[string]types.AttributeValue{
		"key": &types.AttributeValueMemberS{Value: "value"},
	}

	cipherText, err := ic.Encrypt(context.Background(), item)
	if err != nil {
		t.Fatalf("Encrypt() error = %v, want nil", err)
	}

	plainText, err := ic.Decrypt(context.Background(), cipherText)
	if err != nil {
		t.Fatalf("Decrypt() error = %v, want nil", err)
	}

	if len(plainText) != 1 {
		t.Fatalf("Decrypt() = %v, want 1", len(plainText))
	}

	if plainText["key"].(*types.AttributeValueMemberS).Value != "value" {
		t.Fatalf("Decrypt() = %v, want value", plainText["key"].(*types.AttributeValueMemberS).Value)
	}
}
