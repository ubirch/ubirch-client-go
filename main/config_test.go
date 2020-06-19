package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestConfig(t *testing.T) {
	configBytes := []byte(`{"devices":null,"secret":"MTIzNDU2Nzg5MDU2Nzg5MA==","env":"","DSN":"","staticKeys":false,"keys":null,"TLS":false,"TLSCertFile":"","TLSKeyFile":"","CORS":false,"CORS_origins":null,"debug":false,"SecretBytes":null,"KeyService":"","Niomon":"","VerifyService":""}`)

	config := &Config{}

	if err := json.Unmarshal(configBytes, config); err != nil {
		t.Errorf("Failed to unmarshal json config: %s", err)
	}

	// FIXME
	//if !bytes.Equal(config.SecretBytes, []byte("1234567890567890")) {
	//    t.Errorf("Failed to load secret from config")
	//}

	jsonBytes, err := json.Marshal(config)
	if err != nil {
		t.Errorf("Failed to serialize config")
	}

	if !bytes.Equal(configBytes, jsonBytes) {
		t.Errorf("Failed to serialize config to json: got %s expected %s", jsonBytes, configBytes)
	}
}
