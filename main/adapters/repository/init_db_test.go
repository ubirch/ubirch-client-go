package repository

import (
	"github.com/ubirch/ubirch-client-go/main/config"
	"testing"
)

func Test_getAllIdentitiesFromLegacyCtx(t *testing.T) {
	config.Config{
		Devices: map[string]string{
			"9128397a-57bb-4632-a8c0-3714e154e80c": "E00939AB-D010-4CE3-9397-701A1E75C0C7",
			"89524305-F81B-41A9-8800-D6DBC76FAA88": "D12825C6-1EE7-43C1-A5FF-29DA0F801304",
			"B248EA39-6463-4517-B702-D27518598921": "E6124277-5DD9-4B6D-8649-464830ECD4E9",
			"02E63CB8-2C56-4CEE-A50B-E52342138118": "6B523BF0-F345-45DF-8725-CCDB10A5F167",
		},
		Secret16Base64:   "MTIzNDU2Nzg5MDEyMzQ1Ng==",
		Secret32Base64:   "sdSjtMh6C2oNgsiVcPx89RgcNYl8L6R9PhWU3iGIL+k=",
		RegisterAuth:     "",
		Env:              "",
		PostgresDSN:      "",
		CSR_Country:      "",
		CSR_Organization: "",
		TCP_addr:         "",
		TLS:              false,
		TLS_CertFile:     "",
		TLS_KeyFile:      "",
		CORS:             false,
		CORS_Origins:     nil,
		Debug:            false,
		LogTextFormat:    false,
		SecretBytes32:    nil,
		KeyService:       "",
		IdentityService:  "",
		Niomon:           "",
		VerifyService:    "",
		ConfigDir:        "",
	}
	Migrate()
}
