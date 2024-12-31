package dyno

import (
	"context"
	"fmt"
	"reflect"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func ExampleItemCrypter() {
	// Create a new ItemCrypter with a random key.
	c, err := NewAESCrypter([]byte("encrypt-password"))
	if err != nil {
		panic(err)
	}

	ctx := context.Background()

	const key = "key"
	lastEvaluatedKey := map[string]types.AttributeValue{
		key: &types.AttributeValueMemberS{Value: "value"},
	}

	// Encrypt an item.
	encrypted, err := c.Encrypt(ctx, lastEvaluatedKey)
	if err != nil {
		panic(err)
	}

	// Decrypt the item.
	decrypted, err := c.Decrypt(ctx, encrypted)
	if err != nil {
		panic(err)
	}

	if !reflect.DeepEqual(lastEvaluatedKey, decrypted) {
		panic("decrypted item does not match original item")
	}

	value := decrypted[key]
	val := value.(*types.AttributeValueMemberS)
	fmt.Printf("%s: %s\n", key, val.Value)

	// Output: key: value
}
