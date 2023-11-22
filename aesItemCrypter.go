// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dyno

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"golang.org/x/crypto/pbkdf2"
)

// NewAesItemCrypter creates a new ItemCrypter that uses AES encryption.
func NewAesItemCrypter(password, salt []byte) (ItemCrypter, error) {
	key := pbkdf2.Key(password, salt, 4096, 32, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &aesCryptedItem{
		block: block,
	}, nil
}

type aesCryptedItem struct {
	block cipher.Block
}

// Encrypt encrypts a dynamodb item along with an encryption context.
func (c *aesCryptedItem) Encrypt(ctx context.Context,
	item map[string]types.AttributeValue,
) (string, error) {
	// Marshal the item into a JSON string
	it, err := marshalJSON(item)
	if err != nil {
		return "", err
	}
	c.block.Encrypt(it, it)
	return base64.StdEncoding.EncodeToString(it), nil
}

// Decrypt decrypts a dynamodb item along with an encryption context.
// The item must have been encrypted with the same encryption context.
func (c *aesCryptedItem) Decrypt(
	ctx context.Context,
	item string,
) (map[string]types.AttributeValue, error) {
	// Decrypt the item with kmsKeyID
	decodedItem, err := base64.StdEncoding.DecodeString(item)
	if err != nil {
		return nil, err
	}
	c.block.Decrypt(decodedItem, decodedItem)

	// Unmarshal the item into a map[string]types.AttributeValue
	it := map[string]types.AttributeValue{}
	if err := json.Unmarshal(decodedItem, &it); err != nil {
		return nil, err
	}

	return it, nil
}
