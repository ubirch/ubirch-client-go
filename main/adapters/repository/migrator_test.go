package repository

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-client-go/main/config"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

const (
	testSecret16Base64 = "Z+08XlrEAkTf3Ss7eyMrCg=="
	testSecret32Base64 = "CXbgnOK9QdAB44UaeMCKQIE33iCX4xCPDzbh+sQplRY="
)

func TestMigrate(t *testing.T) {
	conf := setupMigrationTest(t)
	defer cleanUpMigrationTest(t, conf.SqliteDSN)

	err := Migrate(conf, "")
	assert.NoError(t, err)
}

func setupMigrationTest(t *testing.T) *config.Config {
	err := ioutil.WriteFile(contextFileName_Legacy, []byte(legacyProtocolCtxJson), filePerm)
	require.NoError(t, err)

	secretBytes32, _ := base64.StdEncoding.DecodeString(testSecret32Base64)

	return &config.Config{
		Devices:            devices,
		Secret16Base64:     testSecret16Base64,
		SecretBytes32:      secretBytes32,
		SqliteDSN:          filepath.Join(t.TempDir(), "test.db?_pragma=journal_mode(WAL)&_txlock=exclusive&_pragma=busy_timeout(1000)"),
		DbMaxConns:         0,
		KdMaxTotalMemMiB:   4,
		KdParamMemMiB:      2,
		KdParamTime:        1,
		KdParamParallelism: 2,
	}
}

func cleanUpMigrationTest(t *testing.T, dsn string) {
	err := os.Remove(contextFileName_Legacy)
	if !os.IsNotExist(err) {
		assert.NoError(t, err)
	}

	err = os.Remove(keyFileName)
	if !os.IsNotExist(err) {
		assert.NoError(t, err)
	}

	err = os.RemoveAll(signatureDirName)
	if !os.IsNotExist(err) {
		assert.NoError(t, err)
	}

	err = os.RemoveAll(authTokenDirName)
	if !os.IsNotExist(err) {
		assert.NoError(t, err)
	}

	db, err := sql.Open(SQLite, dsn)
	require.NoError(t, err)

	_, err = db.Exec(fmt.Sprintf("DROP TABLE %s;", IdentityTableName))
	assert.NoError(t, err)

	_, err = db.Exec(fmt.Sprintf("DROP TABLE %s;", VersionTableName))
	assert.NoError(t, err)

	err = db.Close()
	assert.NoError(t, err)
}

const legacyProtocolCtxJson = `{
  "Crypto": {
    "Keystore": {
      "58999fc8-1c9b-4fc9-9d67-ce6223037dea": "7dl0sHbJnXCwPWiVDAx5UqwKiept2I5Lr15uFR1E0M18bemSph2h58ccfVSKSfj8htrYvLJHoVtLmq63ZZ9qwOKki/+ug8sqknLt3TjfAEnz3v5vYRmd5AxRVAFEdiYt6V4r9+R8Y4oZiJGEzGr9UFLN/V0waibWK5tHZ69eMYiOFJUKd4L+G7HWUJ9BJvsOStNOgIkJhk9eOE+7Ix6zpzEvsOf0xed+ZJzP6hfWkSwQhZPawZsShk9H4gr1Sju3",
      "68999fc8-1c9b-4fc9-9d67-ce6223037dea": "/5bOrMeqtZJAH7JBYzX2QJzSM5nhoOh7lmO+uG7C/opfV2kiVp56nbjWFmXhSqjrUHBrVgjhSIlziD5Ow1Dx+8b/+79hus/D/lNA5iEJhab4o7B0J3Zt7PLiMkUo5eWvsbXfCUd/bOGjV+N4u1B2mmSPmUqLeu/N7mJMynA1xRoSrEXnBWgBm5nBOABkkFDYBwg09hrPn5fOrn1cg87osl/cJBcZvjZB0I7MYZ7OmBf4sf+mO62zYvzMzoW455VG",
      "78999fc8-1c9b-4fc9-9d67-ce6223037dea": "xy9FRVPOn20YJV3cK0FB31TnQN4eKInzGiQbCdZmvaya5x095n0jVBPokQvOg0sCouyCwzHexYiTaKF7Ezfe6H5b7IoxknICCQxb0k3iFVGBMwHA99ZoBn4aUENgsgV3UsLGzX2rBjenPuz8iq0hU3eaI/sZMPVSsN4qs83doXMfMDGc9GQdNfxPASKboyi2p3cFmw2axcOextY3YYWZJHVQa+zze10PrT2TFjezpyMih0weqYCRTTg9BWyi0d7X",
      "88999fc8-1c9b-4fc9-9d67-ce6223037dea": "tBKjsCdP8opUns/TGVyIdY79OUutKUlhSBnOzlAABGw7EbukjPCIRc17SynRvWF01svj0Ykb+vtd2xvxXFek9hof3KQsKYr0XiykNqV5pE68mq0BytyRp47ch1aH5jHmskp9G7N8wZX+OqYWY3T5Y5nQuH101OwShohwxAOczR3vQgctbVuVUQcx0XsBGI/jbZPQplAIO9S6L9OcYSiGs7JW8INlNMWUD/EyxqG35rcHQm8Ge4wkKJViQB8+pRak",
      "_58999fc8-1c9b-4fc9-9d67-ce6223037dea": "olHwjZjmaQ+DF/BRjXZ1DGOeC1e9UPUHbNxqwj7nCkfFmIi1o3HlijIauBcnrGrkvTXIkxKFYEGiFAlXogiYxFqblqOTR5dWRcCEM2PhWww96p6+vs3P/lBCYb83eHuXKg8pbWU9zWvvrvy47mFnMxj/R2HQi4r2UyWad3hrY7z/EY5FNYOz6OnPGZmEZVpn8cIQk/KBIMKJ+UhbVHEYz1SjCCe8wi1H5lO6mNtZgv7JQqMyEtwqh69bCpeVO0v0kbCl82as9kTNynfQibQDoTv4vc57sHjD/NcDAHgrm9eAg2vkGED/VA==",
      "_68999fc8-1c9b-4fc9-9d67-ce6223037dea": "JtctXKoBi7Q1/eswAZN+bSvlddZewg1r+WgGuxqCTB4+C/kVG/E46BJCgJwXjkbgRhmFxy9wjyiHBAf3GfLkk/p0fzhlh71jRVyn8f9ucWQJOlV0QckpEc5+u1zeUY9uNnO5VfJCMOsxrFarWljQtYXK1K1EVjL+DTjbf6TaSRDpZa0b6x7hWqBjHe22XuVKASJA5XOAa0GW6FFZ7eAbZGOz6xLZsbR7aFYODwJBO/mc5VY+Ljb012r512os5f1y+z1ouSHbpb4H5s0vrRayn6XiHx6eHEfPRhU6tjL+Ha4ndpdRPOWPPQ==",
      "_78999fc8-1c9b-4fc9-9d67-ce6223037dea": "efmz7GoJHGrmQ3cL3tnXazAVW0XKfsW6COosNN0PFquXjXs68rqZDVnkQlTdeam83BD1Xc92ZWShVLHzT9o/JENsxE/pSQj3SM0QNC1kwNfYCleYPCc4bnu1yVMgVpuLfGYGRsyk5vNTU7ogVBKpsGrAFoMixyDnlIi2fbcG7jZT/rpgUWNAMGdJeruIdMiX8HVTyYwZHwOcJqxNMGfM4ohBiA+T6mYh4nlBmLZ1nIOqf/Vl2zpOsvpWLDWcikQSMsJq+ychHB1vRJwCIb9APLZ9f/z+T1hQANpoIVunlAN4Y0uXlFo2UQ==",
      "_88999fc8-1c9b-4fc9-9d67-ce6223037dea": "tYTNIBtYgIgfFEb1t2UV5D0IS/rYsxWbYAPT1PDRm/poqhi8GJx/6pDRSvoUS2pwhHqHF2XViH3WdUh8wCJM4XN9VNveaa7gK7RoK1E/fkV3CLhr/3nszULIchO8xEGVNomoOi5r+wLNE6Fb4Q2BUGcZEA8cYFcbPEI3tttCDhGq8nzvIqdiI0cdyKxZ11A4Xnr6K6Who3GdbtszkSGGxO3JW6JjVQkDorwq70TwQXc7nBOKP9UuizO582zaa0rxzC89I1ybiZ5ICtcx2n7WbCanIaZlWB01J0lcO9jb29hqgs04FomPcg=="
    },
    "Names": {
      "58999fc8-1c9b-4fc9-9d67-ce6223037dea": "58999fc8-1c9b-4fc9-9d67-ce6223037dea",
      "68999fc8-1c9b-4fc9-9d67-ce6223037dea": "68999fc8-1c9b-4fc9-9d67-ce6223037dea",
      "78999fc8-1c9b-4fc9-9d67-ce6223037dea": "78999fc8-1c9b-4fc9-9d67-ce6223037dea",
      "88999fc8-1c9b-4fc9-9d67-ce6223037dea": "88999fc8-1c9b-4fc9-9d67-ce6223037dea"
    }
  },
  "Signatures": {
    "58999fc8-1c9b-4fc9-9d67-ce6223037dea": "4m52sCx5uW3XY7oNnZul3DZRRcmhPFmo0HoQeIrw8AVca6CWQKtn3+NkbrdOeWd/LVor7WQXREubUsbo9BgpqQ==",
    "68999fc8-1c9b-4fc9-9d67-ce6223037dea": "Cw+wZR1/6d4H+5tC8fvmjRaoYDX3HJnuacPQob0uxRvwDm6bYF8HqOVMMrdKZLnqXv+NvTexsd0lrVxjJ4KMTA==",
    "78999fc8-1c9b-4fc9-9d67-ce6223037dea": "0KTGDy4KfNch8qj6z5LgcwszOY26EiJddnhxy2znMMqDxHUQajdwaz4WqQ1ZC3JOmwtCuMlm3OE8A5I2nzTaXA==",
    "88999fc8-1c9b-4fc9-9d67-ce6223037dea": "RMr/tuHxSIzQE0Lx7JLZwAAjcVB4okaWOl6ptsKXYE5JbB1L5yqX6exBvcbVZ+BeINkhSn4o7cVp3cIHh6QiSQ=="
  }
}`

var devices = map[string]string{
	"58999fc8-1c9b-4fc9-9d67-ce6223037dea": "Pv3cAWvHnde/sxcM7fA02g==",
	"68999fc8-1c9b-4fc9-9d67-ce6223037dea": "2PG3un+XgXt4TyCtSZNO2A==",
	"78999fc8-1c9b-4fc9-9d67-ce6223037dea": "mlkwF1XW4xEAM2TjUBQCPw==",
	"88999fc8-1c9b-4fc9-9d67-ce6223037dea": "PQHlke6G4wFagizLCMwI1w==",
}
