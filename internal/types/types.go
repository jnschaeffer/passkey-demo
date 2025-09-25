package types

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/go-webauthn/webauthn/webauthn"
)

type ID [64]byte

func NewID() (ID, error) {
	var out ID

	rand.Read(out[:])

	return out, nil
}

func NewIDFromBytes(b []byte) (ID, error) {
	if len(b) != 64 {
		return ID{}, errors.New("bad length")
	}

	return ID(b), nil
}

func DecodeID(b64Bytes string) (ID, error) {
	var (
		b   []byte
		err error
	)

	if b, err = base64.StdEncoding.DecodeString(b64Bytes); err != nil {
		return ID{}, err
	}

	return NewIDFromBytes(b)
}

type User struct {
	ID          ID
	Name        string
	Credentials []Credential
}

func (u *User) WebAuthnID() []byte {
	return u.ID[:]
}

func (u *User) WebAuthnName() string {
	return u.Name
}

func (u *User) WebAuthnDisplayName() string {
	return u.WebAuthnName()
}

func (u *User) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, len(u.Credentials))

	for _, c := range u.Credentials {
		out = append(out, c.WebAuthn)
	}

	return out
}

type Session struct {
	ID       ID
	WebAuthn webauthn.SessionData
}

type Credential struct {
	WebAuthn webauthn.Credential
}
