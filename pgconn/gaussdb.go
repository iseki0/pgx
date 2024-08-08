package pgconn

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
)

func gaussGenerateKFromPBKDF2(password string, random64Code [64]byte, token [8]byte, serverSignature [64]byte, checkServerSign bool, serverIteration int) (rs []byte, e error) {
	defer func() {
		if e != nil {
			e = fmt.Errorf("gaussGenerateKFromPBKDF2: %w", e)
		}
	}()
	var random32Code [32]byte
	var n int
	n, e = hex.Decode(random32Code[:], random64Code[:])
	if e != nil {
		return
	}
	if n != 32 {
		e = errors.New("n != 32")
	}
	var key = pbkdf2.Key([]byte(password), random32Code[:], serverIteration, 32, sha1.New)
	var serverKey = doSHA256HMac(key, []byte("Sever Key"))
	var clientKey = doSHA256HMac(key, []byte("Client Key"))
	var storedKey = doSHA256(clientKey)
	var tokenBytes [4]byte
	n, e = hex.Decode(tokenBytes[:], token[:])
	if e != nil {
		return
	}
	if n != 4 {
		e = errors.New("n != 8")
	}
	var clientSignature = doSHA256HMac(serverKey, tokenBytes[:])
	_ = clientSignature
	var hmacResult = doSHA256HMac(storedKey, tokenBytes[:])
	var hValue = make([]byte, len(clientKey))
	for i := range clientKey {
		hValue[i] = hmacResult[i] ^ clientKey[i]
	}
	rs = make([]byte, len(hValue)*2)
	hex.Encode(rs, hValue)
	return
}

func doSHA256HMac(key []byte, input []byte) []byte {
	var h = hmac.New(sha256.New, key)
	_, e := h.Write(input)
	if e != nil {
		panic(e)
	}
	return h.Sum(nil)
}

func doSHA256(input []byte) []byte {
	var h = sha256.New()
	_, e := h.Write(input)
	if e != nil {
		panic(e)
	}
	return h.Sum(nil)
}
