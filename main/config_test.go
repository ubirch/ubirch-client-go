package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestConfig(t *testing.T) {
	configBytes := []byte(`{"devices":null,"secret":"MTIzNDU2Nzg5MDU2Nzg5MA==","DSN":"","staticKeys":false,"env":"","TLS":false,"TLS_CertFile":"","TLS_KeyFile":"","debug":false,"KeyService":"","Niomon":"","VerifyService":"","SecretBytes":null}`)

	config := &Config{}

	if err := json.Unmarshal(configBytes, config); err != nil {
		t.Errorf("Failed to unmarshal json config: %s", err)
	}

	// FIXME
	//if !bytes.Equal(config.SecretBytes, []byte("1234567890567890")) {
	//	t.Errorf("Failed to load secret from config")
	//}

	jsonBytes, err := json.Marshal(config)
	if err != nil {
		t.Errorf("Failed to serialize secret")
	}

	if !bytes.Equal(configBytes, jsonBytes) {
		t.Errorf("Failed to serialize config to json: got %s expected %s", jsonBytes, configBytes)
	}
}
