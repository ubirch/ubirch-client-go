package config

import (
	"bytes"
	"encoding/json"
	"testing"
)

const expectedConfig = `{"devices":null,"secret":"MTIzNDU2Nzg5MDU2Nzg5MA==","env":"","DSN":"","CSR_country":"","CSR_organization":"","TCP_addr":"","TLS":false,"TLSCertFile":"","TLSKeyFile":"","CORS":false,"CORS_origins":null,"debug":false,"logTextFormat":false,"KeyService":"","IdentityService":"","Niomon":"","VerifyService":""}`

func TestConfig(t *testing.T) {
	configBytes := []byte(expectedConfig)

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
		t.Errorf("Failed to serialize config")
	}

	if !bytes.Equal(configBytes, jsonBytes) {
		t.Errorf("Failed to serialize config to json:\n"+
			"- expected: %s\n"+
			"-      got: %s", configBytes, jsonBytes)
	}
}
