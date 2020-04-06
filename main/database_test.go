package main

import (
	"testing"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

func TestFileDatabase(t *testing.T) {
	p := ExtendedProtocol{}
	p.Crypto = &ubirch.CryptoContext{
		Keystore: ubirch.NewEncryptedKeystore([]byte("16 bytes 0123456")),
		Names:    map[string]uuid.UUID{},
	}
	p.Signatures = map[uuid.UUID][]byte{}
	p.Certificates = map[uuid.UUID]SignedKeyRegistration{}

	testFileStore := FileStore{FilePath: "/tmp/filestore.json"}
	p.DB = &testFileStore

	// we want to see if we are able to save the protocol context in a file
	err := p.saveDB()
	if err != nil {
		t.Errorf("Error saving DB: %s", err)
	}

	// we want to see if we can retrieve the protocol context from the file
	err = p.load()
	if err != nil {
		t.Errorf("Error loading DB: %s", err)
	}
}
