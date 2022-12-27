package repository

import (
	"context"
	"encoding/base64"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-client-go/main/config"
	"os"
	"path/filepath"
	"testing"
)

const (
	testSecret16Base64 = "Z+08XlrEAkTf3Ss7eyMrCg=="
	testSecret32Base64 = "CXbgnOK9QdAB44UaeMCKQIE33iCX4xCPDzbh+sQplRY="

	testUUID = "21c033cf-38af-466e-b5da-32f0a3ab6020"
)

func TestMigrate(t *testing.T) {
	testCases := []struct {
		name   string
		setDSN func(*testing.T, *config.Config, string) error
	}{
		{
			name: "postgres migration",
			setDSN: func(t *testing.T, c *config.Config, _ string) error {
				// this test communicates with the actual postgres database
				if testing.Short() {
					t.Skipf("skipping integration test %s in short mode", t.Name())
				}

				dbConf, err := getConfig()
				if err != nil {
					return err
				}
				c.DbDriver = PostgreSQL
				c.DbDSN = dbConf.DbDSN
				return nil
			},
		},
		{
			name: "sqlite migration",
			setDSN: func(t *testing.T, c *config.Config, configDir string) error {
				c.DbDriver = SQLite
				c.DbDSN = filepath.Join(configDir, testSQLiteDSN)
				return nil
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			conf := getMigrationConfig()
			tmp := t.TempDir()

			err := c.setDSN(t, conf, tmp)
			require.NoError(t, err)

			err = setupMigrationTest(tmp)
			require.NoError(t, err)
			defer cleanUpMigrationTest(t, conf, tmp)

			err = Migrate(conf, tmp)
			require.NoError(t, err)

			verifyMigration(t, conf)
		})
	}
}

func setupMigrationTest(configDir string) error {
	legacyCtxFile := filepath.Join(configDir, contextFileName_Legacy)

	return os.WriteFile(legacyCtxFile, []byte(legacyProtocolCtxJson), filePerm)
}

func getMigrationConfig() *config.Config {
	secretBytes32, _ := base64.StdEncoding.DecodeString(testSecret32Base64)

	return &config.Config{
		Devices:            devices,
		Secret16Base64:     testSecret16Base64,
		SecretBytes32:      secretBytes32,
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}
}

func cleanUpMigrationTest(t *testing.T, c *config.Config, configDir string) {
	// assert legacy files were cleaned up after migration
	_, err := os.Stat(filepath.Join(configDir, contextFileName_Legacy))
	assert.Truef(t, os.IsNotExist(err), "%s has not been cleaned up after migration", contextFileName_Legacy)

	_, err = os.Stat(filepath.Join(configDir, contextFileName_Legacy+".bck"))
	assert.Truef(t, os.IsNotExist(err), "%s has not been cleaned up after migration", contextFileName_Legacy+".bck")

	//_, err = os.Stat(filepath.Join(configDir, keyFileName))
	//assert.Truef(t, os.IsNotExist(err), "%s has not been cleaned up after migration", keyFileName)
	//
	//_, err = os.Stat(filepath.Join(configDir, keyFileName+".bck"))
	//assert.Truef(t, os.IsNotExist(err), "%s has not been cleaned up after migration", keyFileName+".bck")
	//
	//_, err = os.Stat(filepath.Join(configDir, signatureDirName))
	//assert.Truef(t, os.IsNotExist(err), "%s has not been cleaned up after migration", signatureDirName)

	ctxManager, err := GetContextManager(c)
	require.NoError(t, err)

	dm, ok := ctxManager.(*DatabaseManager)
	require.True(t, ok)

	cleanUpDB(t, dm)
}

func verifyMigration(t *testing.T, c *config.Config) {
	ctxManager, err := GetContextManager(c)
	require.NoError(t, err)

	p, err := NewExtendedProtocol(ctxManager, c)
	require.NoError(t, err)

	i, err := p.LoadIdentity(uuid.MustParse(testUUID))
	require.NoError(t, err)

	assert.Equal(t,
		"4m52sCx5uW3XY7oNnZul3DZRRcmhPFmo0HoQeIrw8AVca6CWQKtn3+NkbrdOeWd/LVor7WQXREubUsbo9BgpqQ==",
		base64.StdEncoding.EncodeToString(i.Signature))

	ok, found, err := p.CheckAuth(context.Background(), uuid.MustParse(testUUID), "Pv3cAWvHnde/sxcM7fA02g==")
	assert.NoError(t, err)
	assert.True(t, found)
	assert.True(t, ok)

	signature, err := p.Crypto.Sign(uuid.MustParse(testUUID), []byte("message"))
	require.NoError(t, err)

	ok, err = p.Crypto.Verify(uuid.MustParse(testUUID), []byte("message"), signature)
	assert.NoError(t, err)
	assert.True(t, ok)
}

const legacyProtocolCtxJson = `{
  "Crypto": {
    "Keystore": {
      "21c033cf-38af-466e-b5da-32f0a3ab6020": "7dl0sHbJnXCwPWiVDAx5UqwKiept2I5Lr15uFR1E0M18bemSph2h58ccfVSKSfj8htrYvLJHoVtLmq63ZZ9qwOKki/+ug8sqknLt3TjfAEnz3v5vYRmd5AxRVAFEdiYt6V4r9+R8Y4oZiJGEzGr9UFLN/V0waibWK5tHZ69eMYiOFJUKd4L+G7HWUJ9BJvsOStNOgIkJhk9eOE+7Ix6zpzEvsOf0xed+ZJzP6hfWkSwQhZPawZsShk9H4gr1Sju3",
      "b8eaf649-3eaa-472e-9b69-0c6793254c76": "/5bOrMeqtZJAH7JBYzX2QJzSM5nhoOh7lmO+uG7C/opfV2kiVp56nbjWFmXhSqjrUHBrVgjhSIlziD5Ow1Dx+8b/+79hus/D/lNA5iEJhab4o7B0J3Zt7PLiMkUo5eWvsbXfCUd/bOGjV+N4u1B2mmSPmUqLeu/N7mJMynA1xRoSrEXnBWgBm5nBOABkkFDYBwg09hrPn5fOrn1cg87osl/cJBcZvjZB0I7MYZ7OmBf4sf+mO62zYvzMzoW455VG",
      "80ea9750-ba39-446b-83f4-15724ebb95dd": "xy9FRVPOn20YJV3cK0FB31TnQN4eKInzGiQbCdZmvaya5x095n0jVBPokQvOg0sCouyCwzHexYiTaKF7Ezfe6H5b7IoxknICCQxb0k3iFVGBMwHA99ZoBn4aUENgsgV3UsLGzX2rBjenPuz8iq0hU3eaI/sZMPVSsN4qs83doXMfMDGc9GQdNfxPASKboyi2p3cFmw2axcOextY3YYWZJHVQa+zze10PrT2TFjezpyMih0weqYCRTTg9BWyi0d7X",
      "cecc55fb-5f74-4a33-87ec-340158f96260": "tBKjsCdP8opUns/TGVyIdY79OUutKUlhSBnOzlAABGw7EbukjPCIRc17SynRvWF01svj0Ykb+vtd2xvxXFek9hof3KQsKYr0XiykNqV5pE68mq0BytyRp47ch1aH5jHmskp9G7N8wZX+OqYWY3T5Y5nQuH101OwShohwxAOczR3vQgctbVuVUQcx0XsBGI/jbZPQplAIO9S6L9OcYSiGs7JW8INlNMWUD/EyxqG35rcHQm8Ge4wkKJViQB8+pRak",
      "_21c033cf-38af-466e-b5da-32f0a3ab6020": "olHwjZjmaQ+DF/BRjXZ1DGOeC1e9UPUHbNxqwj7nCkfFmIi1o3HlijIauBcnrGrkvTXIkxKFYEGiFAlXogiYxFqblqOTR5dWRcCEM2PhWww96p6+vs3P/lBCYb83eHuXKg8pbWU9zWvvrvy47mFnMxj/R2HQi4r2UyWad3hrY7z/EY5FNYOz6OnPGZmEZVpn8cIQk/KBIMKJ+UhbVHEYz1SjCCe8wi1H5lO6mNtZgv7JQqMyEtwqh69bCpeVO0v0kbCl82as9kTNynfQibQDoTv4vc57sHjD/NcDAHgrm9eAg2vkGED/VA==",
      "_b8eaf649-3eaa-472e-9b69-0c6793254c76": "JtctXKoBi7Q1/eswAZN+bSvlddZewg1r+WgGuxqCTB4+C/kVG/E46BJCgJwXjkbgRhmFxy9wjyiHBAf3GfLkk/p0fzhlh71jRVyn8f9ucWQJOlV0QckpEc5+u1zeUY9uNnO5VfJCMOsxrFarWljQtYXK1K1EVjL+DTjbf6TaSRDpZa0b6x7hWqBjHe22XuVKASJA5XOAa0GW6FFZ7eAbZGOz6xLZsbR7aFYODwJBO/mc5VY+Ljb012r512os5f1y+z1ouSHbpb4H5s0vrRayn6XiHx6eHEfPRhU6tjL+Ha4ndpdRPOWPPQ==",
      "_80ea9750-ba39-446b-83f4-15724ebb95dd": "efmz7GoJHGrmQ3cL3tnXazAVW0XKfsW6COosNN0PFquXjXs68rqZDVnkQlTdeam83BD1Xc92ZWShVLHzT9o/JENsxE/pSQj3SM0QNC1kwNfYCleYPCc4bnu1yVMgVpuLfGYGRsyk5vNTU7ogVBKpsGrAFoMixyDnlIi2fbcG7jZT/rpgUWNAMGdJeruIdMiX8HVTyYwZHwOcJqxNMGfM4ohBiA+T6mYh4nlBmLZ1nIOqf/Vl2zpOsvpWLDWcikQSMsJq+ychHB1vRJwCIb9APLZ9f/z+T1hQANpoIVunlAN4Y0uXlFo2UQ==",
      "_cecc55fb-5f74-4a33-87ec-340158f96260": "tYTNIBtYgIgfFEb1t2UV5D0IS/rYsxWbYAPT1PDRm/poqhi8GJx/6pDRSvoUS2pwhHqHF2XViH3WdUh8wCJM4XN9VNveaa7gK7RoK1E/fkV3CLhr/3nszULIchO8xEGVNomoOi5r+wLNE6Fb4Q2BUGcZEA8cYFcbPEI3tttCDhGq8nzvIqdiI0cdyKxZ11A4Xnr6K6Who3GdbtszkSGGxO3JW6JjVQkDorwq70TwQXc7nBOKP9UuizO582zaa0rxzC89I1ybiZ5ICtcx2n7WbCanIaZlWB01J0lcO9jb29hqgs04FomPcg=="
    },
    "Names": {
      "21c033cf-38af-466e-b5da-32f0a3ab6020": "21c033cf-38af-466e-b5da-32f0a3ab6020",
      "b8eaf649-3eaa-472e-9b69-0c6793254c76": "b8eaf649-3eaa-472e-9b69-0c6793254c76",
      "80ea9750-ba39-446b-83f4-15724ebb95dd": "80ea9750-ba39-446b-83f4-15724ebb95dd",
      "cecc55fb-5f74-4a33-87ec-340158f96260": "cecc55fb-5f74-4a33-87ec-340158f96260"
    }
  },
  "Signatures": {
    "21c033cf-38af-466e-b5da-32f0a3ab6020": "4m52sCx5uW3XY7oNnZul3DZRRcmhPFmo0HoQeIrw8AVca6CWQKtn3+NkbrdOeWd/LVor7WQXREubUsbo9BgpqQ==",
    "b8eaf649-3eaa-472e-9b69-0c6793254c76": "Cw+wZR1/6d4H+5tC8fvmjRaoYDX3HJnuacPQob0uxRvwDm6bYF8HqOVMMrdKZLnqXv+NvTexsd0lrVxjJ4KMTA==",
    "80ea9750-ba39-446b-83f4-15724ebb95dd": "0KTGDy4KfNch8qj6z5LgcwszOY26EiJddnhxy2znMMqDxHUQajdwaz4WqQ1ZC3JOmwtCuMlm3OE8A5I2nzTaXA==",
    "cecc55fb-5f74-4a33-87ec-340158f96260": "RMr/tuHxSIzQE0Lx7JLZwAAjcVB4okaWOl6ptsKXYE5JbB1L5yqX6exBvcbVZ+BeINkhSn4o7cVp3cIHh6QiSQ=="
  }
}`

var devices = map[string]string{
	"21c033cf-38af-466e-b5da-32f0a3ab6020": "Pv3cAWvHnde/sxcM7fA02g==",
	"b8eaf649-3eaa-472e-9b69-0c6793254c76": "2PG3un+XgXt4TyCtSZNO2A==",
	"80ea9750-ba39-446b-83f4-15724ebb95dd": "mlkwF1XW4xEAM2TjUBQCPw==",
	"cecc55fb-5f74-4a33-87ec-340158f96260": "PQHlke6G4wFagizLCMwI1w==",
}
