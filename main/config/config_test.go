package config

import (
	"bytes"
	"encoding/json"
	"testing"
)

const expectedConfig = `{"devices":null,"secret":"MTIzNDU2Nzg5MDU2Nzg5MA==","secret32":"VsCwmGssk7Ho2APyq1reGAKkB/+e8GlRfhM3NbYQWPU=","registerAuth":"test123","env":"","postgresDSN":"","dbMaxConns":0,"CSR_country":"","CSR_organization":"","TCP_addr":"","TLS":false,"TLSCertFile":"","TLSKeyFile":"","CORS":false,"CORS_origins":null,"debug":false,"logTextFormat":false,"SecretBytes32":null,"KeyService":"","IdentityService":"","Niomon":"","VerifyService":"","ConfigDir":""}`

func TestConfig(t *testing.T) {
	configBytes := []byte(expectedConfig)

	config := &Config{}

	if err := json.Unmarshal(configBytes, config); err != nil {
		t.Fatalf("Failed to unmarshal json config: %s", err)
	}

	// FIXME
	//if !bytes.Equal(config.secretBytes, []byte("1234567890567890")) {
	//	t.Errorf("Failed to load secret from config")
	//}

	jsonBytes, err := json.Marshal(config)
	if err != nil {
		t.Errorf("Failed to serialize config")
	}

	if !bytes.Equal(configBytes, jsonBytes) {
		t.Errorf("Failed to serialize config to json:\n"+
			"- expected: %s\n"+
			"-      got: %s", configBytes, jsonBytes)
	}
}
