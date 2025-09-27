package types

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/go-webauthn/webauthn/webauthn"
)

// ID represents a fairly large random identifier. This type uses 64 bytes per the WebAuthn recommendations around user ID length.
type ID [64]byte

// NewID creates a new ID.
func NewID() (ID, error) {
	var out ID

	rand.Read(out[:])

	return out, nil
}

// NewIDFromBytes parses a byte array into an ID. It returns an error if b is not exactly 64 bytes in length.
func NewIDFromBytes(b []byte) (ID, error) {
	if len(b) != 64 {
		return ID{}, errors.New("bad length")
	}

	return ID(b), nil
}

// DecodeID decodes a Base64-encoded string into an ID. It returns an error if the string is not valid Base64 or the resulting byte array is not exactly 64 bytes in length.
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

// User represents a user that owns one or more credentials (passkeys).
type User struct {
	ID          ID
	Name        string
	Credentials []Credential
}

// WebAuthnID returns the user's ID as a byte slice.
func (u *User) WebAuthnID() []byte {
	return u.ID[:]
}

// WebAuthnName returns the user's username.
func (u *User) WebAuthnName() string {
	return u.Name
}

// WebAuthnDisplayName returns the user's display name.
func (u *User) WebAuthnDisplayName() string {
	return u.WebAuthnName()
}

// WebAuthnCredentials returns a slice of credentials belonging to the user.
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, len(u.Credentials))

	for _, c := range u.Credentials {
		out = append(out, c.WebAuthn)
	}

	return out
}

// Session represents a WebAuthn ceremony session. This type is used for both registration and login.
type Session struct {
	ID       ID
	WebAuthn webauthn.SessionData
}

// Credential represents a single WebAuthn credential.
type Credential struct {
	WebAuthn webauthn.Credential
}
