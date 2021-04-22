package keystr

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/ubirch/go.crypto/keystore"
)

// Keystorer contains the methods that must be implemented by the keystore
// implementation.
type Keystorer interface {
	GetPrivateKey(id uuid.UUID) ([]byte, error)
	SetPrivateKey(id uuid.UUID, key []byte) error

	GetPublicKey(id uuid.UUID) ([]byte, error)
	SetPublicKey(id uuid.UUID, key []byte) error
}

// EncryptedKeystore is the reference implementation for a simple keystr.
// The secret has to be 16 Bytes long
type EncryptedKeystore struct {
	*Keystore
	Secret []byte
}

// Ensure EncryptedKeystore implements the Keystorer interface
var _ Keystorer = (*EncryptedKeystore)(nil)

// NewEncryptedKeystore returns a new freshly initialized Keystore
func NewEncryptedKeystore(secret []byte) *EncryptedKeystore {
	if len(secret) != 16 {
		return nil
	}
	return &EncryptedKeystore{
		Keystore: ,
		Secret:   secret,
	}
}

// GetKey returns a Key from the Keystore
func (enc *EncryptedKeystore) getKey(keyname string) ([]byte, error) {
	return enc.Keystore.Get(keyname, enc.Secret)
}

// SetKey sets a key in the Keystore
func (enc *EncryptedKeystore) setKey(keyname string, keyvalue []byte) error {
	return enc.Keystore.Set(keyname, keyvalue, enc.Secret)
}

func (enc *EncryptedKeystore) GetPrivateKey(id uuid.UUID) ([]byte, error) {
	return enc.getKey(privKeyEntryTitle(id))
}

func (enc *EncryptedKeystore) SetPrivateKey(id uuid.UUID, key []byte) error {
	return enc.setKey(privKeyEntryTitle(id), key)
}

func (enc *EncryptedKeystore) GetPublicKey(id uuid.UUID) ([]byte, error) {
	return enc.getKey(pubKeyEntryTitle(id))
}

func (enc *EncryptedKeystore) SetPublicKey(id uuid.UUID, key []byte) error {
	return enc.setKey(pubKeyEntryTitle(id), key)
}

// MarshalJSON implements the json.Marshaler interface. The Password will not be
// marshaled.
func (enc *EncryptedKeystore) MarshalJSON() ([]byte, error) {
	return json.Marshal(enc.Keystore)
}

// UnmarshalJSON implements the json.Unmarshaler interface. The struct must not be
// null, and the password will not be read from the json, and needs to be set
// seperately.
func (enc *EncryptedKeystore) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, enc.Keystore)
}

// privKeyEntryTitle returns a string of the Private Key Entry
func privKeyEntryTitle(id uuid.UUID) string {
	return "_" + id.String()
}

// pubKeyEntryTitle returns a string of the Public Key Entry
func pubKeyEntryTitle(id uuid.UUID) string {
	return id.String()
}
