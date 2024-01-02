package dyno

import "encoding/base64"

// Base64Bytes reads a base64 encoded string and decodes it into a byte slice.
// Use it with the envconfig package to read bytes from an environment variable.
type Base64Bytes []byte

func (b *Base64Bytes) Decode(value string) (err error) {
	if b == nil {
		return
	}
	*b, err = base64.StdEncoding.DecodeString(value)
	return
}
