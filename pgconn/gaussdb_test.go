package pgconn

import (
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGaussGenerateKFromPBKDF2(t *testing.T) {
	var b64 [64]byte
	var b8 [8]byte
	copy(b64[:], "0000000000000000000000000000000000000000000000000000000000000000")
	copy(b8[:], "00000000")

	r, e := gaussGenerateKFromPBKDF2("123456", b64, b8, b64, false, 2048)
	assert.NoError(t, e)
	fmt.Println(hex.EncodeToString(r))
}
