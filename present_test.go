package present

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var tests = []struct {
	plain  string
	key    string
	cipher string
}{
	{`0000000000000000`, `00000000000000000000`, `5579C1387B228445`},
	{`0000000000000000`, `FFFFFFFFFFFFFFFFFFFF`, `E72C46C0F5945049`},
	{`FFFFFFFFFFFFFFFF`, `00000000000000000000`, `A112FFC72F68417B`},
	{`FFFFFFFFFFFFFFFF`, `FFFFFFFFFFFFFFFFFFFF`, `3333DCD3213210D2`},
}

func TestPRESENT(t *testing.T) {

	for i, tt := range tests {
		k, _ := hex.DecodeString(tt.key)
		p, _ := hex.DecodeString(tt.plain)
		c, _ := hex.DecodeString(tt.cipher)

		cipher, _ := New(k)

		t.Log(p, k, i)

		cipher.Encrypt(p)

		if !bytes.Equal(p, c) {
			t.Errorf("encrypt(%v,%v)=%v, want %v", tt.plain, tt.key, p, tt.cipher)
		}

		p, _ = hex.DecodeString(tt.plain)

		t.Log(c, k, i)
		cipher.Decrypt(c)

		if !bytes.Equal(p, c) {
			t.Errorf("decrypt(%v,%v)=%v, want %v", tt.cipher, tt.key, p, tt.plain)
		}
	}
}
