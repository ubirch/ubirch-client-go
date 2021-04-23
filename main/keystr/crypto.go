package keystr

// EncryptedKeystore is the reference implementation for a simple keystr.
// The secret has to be 16 Bytes long
type EncryptedKeystore struct {
	Secret []byte
}

// NewEncryptedKeystore returns a new freshly initialized Keystore
func NewEncryptedKeystore(secret []byte) *EncryptedKeystore {
	if len(secret) != 16 {
		return nil
	}
	return &EncryptedKeystore{
		Secret:   secret,
	}
}

func (enc *EncryptedKeystore) Encryt(key string) ([]byte, error) {
	return []byte{0,0,1}, nil
}

func (enc *EncryptedKeystore) Decrypt([]byte) ([]byte, error) {
	return []byte{0,0,1}, nil
}