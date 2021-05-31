package repository

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/ent"
)

const (
	TestTableName = "test_identity"
	TestUUID      = "2336c75d-a14a-47dd-80d9-3cbe9d560433"
	TestPrivKey   = "Qkp+ZVAlEKCQNvI+OCbY7LKcQVW5iKfFMfzedTI3uG0="
	TestPubKey    = "bvXP3mQ42hXpcqo0ms7Lr1n6Q4L5CsS8HXk0mdXlsXLwYjd35jLlX3iHrXMgUH92N8ujbZ3h3TnLk8a0GikUbg=="
	TestSignature = "XqfjRkM0g9swes9osaoptFCFau4Qq3jX+bv+SwPLkUARs8MRm6uRj3VCbvF3JZUlHAEuXmAn849vV9e71KGjDQ=="
	TestAuthToken = "TEST_auth"
)

func TestDatabaseManager_StoreNewIdentity(t *testing.T) {
	conf := &config.Config{}
	err := conf.Load("../../", "config.json")
	if err != nil {
		t.Fatalf("ERROR: unable to load configuration: %s", err)
	}

	dbManager, err := NewSqlDatabaseInfo(conf.PostgresDSN, TestTableName)
	if err != nil {
		t.Fatal(err)
	}

	testIdentity, err := getTestIdentity()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := dbManager.StartTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}

	err = dbManager.StoreNewIdentity(tx, testIdentity)
	if err != nil {
		t.Fatal(err)
	}

	err = dbManager.CloseTransaction(tx, Commit)
	if err != nil {
		t.Fatal(err)
	}

	// clean up
	deleteQuery := fmt.Sprintf("DELETE FROM %s WHERE uid = $1;", TestTableName)
	_, err = dbManager.db.Exec(deleteQuery, testIdentity.Uid)
	if err != nil {
		t.Fatal(err)
	}

	dropTableQuery := fmt.Sprintf("DROP TABLE %s;", TestTableName)
	_, err = dbManager.db.Exec(dropTableQuery)
	if err != nil {
		t.Fatal(err)
	}
}

func getTestIdentity() (*ent.Identity, error) {
	testUid, err := uuid.Parse(TestUUID)
	if err != nil {
		return nil, err
	}
	priv, err := base64.StdEncoding.DecodeString(TestPrivKey)
	if err != nil {
		return nil, err
	}
	pub, err := base64.StdEncoding.DecodeString(TestPubKey)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(TestSignature)
	if err != nil {
		return nil, err
	}
	return &ent.Identity{
		Uid:        testUid.String(),
		PrivateKey: priv,
		PublicKey:  pub,
		Signature:  sig,
		AuthToken:  TestAuthToken,
	}, nil
}
