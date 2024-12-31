package dyno

import "testing"

func TestBase64Bytes(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		var b Base64Bytes
		if err := b.Decode("aGVsbG8gd29ybGQ="); err != nil {
			t.Fatal(err)
		}
		if string(b) != "hello world" {
			t.Fatalf("expected %q, got %q", "hello world", string(b))
		}
	})

	t.Run("invalid", func(t *testing.T) {
		var b Base64Bytes
		if err := b.Decode("hello world"); err == nil {
			t.Fatal("expected error")
		}
	})
}
