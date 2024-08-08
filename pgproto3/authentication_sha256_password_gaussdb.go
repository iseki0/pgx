package pgproto3

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

type GaussSHA256PasswordStoredMethod int32

const (
	GaussSHA256PasswordStoredMethodPlainPassword  GaussSHA256PasswordStoredMethod = 0
	GaussSHA256PasswordStoredMethodMD5Password    GaussSHA256PasswordStoredMethod = 1
	GaussSHA256PasswordStoredMethodSha256Password GaussSHA256PasswordStoredMethod = 2
)

type AuthenticationSHA256PasswordGaussDBResp struct {
	Buf []byte
}

func (a AuthenticationSHA256PasswordGaussDBResp) Decode(data []byte) error {
	//TODO implement me
	panic("implement me")
}

func (a AuthenticationSHA256PasswordGaussDBResp) Encode(dst []byte) ([]byte, error) {
	dst, sp := beginMessage(dst, 'p')
	dst = append(dst, a.Buf...)
	dst = append(dst, 0)
	return finishMessage(dst, sp)
}

func (a AuthenticationSHA256PasswordGaussDBResp) Frontend() {
}

var _ FrontendMessage = (*AuthenticationSHA256PasswordGaussDBResp)(nil)

type AuthenticationSHA256PasswordGaussDB struct {
	PasswordStoredMethod   GaussSHA256PasswordStoredMethod
	Random64Code           [64]byte
	ServerSignature        [64]byte
	ServerSignatureEnabled bool
	Token                  [8]byte
	ServerIteration        int32
}

func (a *AuthenticationSHA256PasswordGaussDB) Decode(data []byte) (e error) {
	defer func() {
		if e != nil {
			e = fmt.Errorf("decoding AuthenticationSHA256PasswordGaussDB: %w", e)
		}
	}()
	var reader = bytes.NewReader(data[4:])
	readBigEndian("PasswordStoredMethod", &e, reader, &a.PasswordStoredMethod)
	if a.PasswordStoredMethod == GaussSHA256PasswordStoredMethodMD5Password {
		return errors.New("not implemented GaussSHA256PasswordStoredMethod: md5")
	}
	if a.PasswordStoredMethod != GaussSHA256PasswordStoredMethodPlainPassword && a.PasswordStoredMethod != GaussSHA256PasswordStoredMethodSha256Password {
		return fmt.Errorf("unsupported GaussSHA256PasswordStoredMethod: %d", a.PasswordStoredMethod)
	}
	readBigEndian("random64code", &e, reader, &a.Random64Code)
	readBigEndian("token", &e, reader, &a.Token)
	if e != nil {
		return
	}
	if reader.Len() == 4 {
		readBigEndian("serverIteration", &e, reader, &a.ServerIteration)
	} else if reader.Len() == 0 {
		return errors.New("protocol version might be 350, not implemented")
	} else {
		// I don't know why the Cloud GaussDB gives a bad signature, but who cares?
		a.ServerIteration = 2048
		readBigEndian("serverSignature", &e, reader, &a.ServerSignature)
	}
	return
}

func (a *AuthenticationSHA256PasswordGaussDB) Encode(dst []byte) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (a *AuthenticationSHA256PasswordGaussDB) Backend() {
}

var _ BackendMessage = (*AuthenticationSHA256PasswordGaussDB)(nil)

func readBigEndian(fieldName string, e *error, reader io.Reader, target any) {
	if *e != nil {
		return
	}
	_e := binary.Read(reader, binary.BigEndian, target)
	if _e != nil {
		*e = fmt.Errorf("reading %s: %w", fieldName, _e)
	}
	return
}
