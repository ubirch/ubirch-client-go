package repository

import (
	"bytes"
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

var (
	testIdentity = initTestIdentity()
)

func TestDatabaseManager(t *testing.T) {
	dbManager, err := initDB()
	if err != nil {
		t.Fatal(err)
	}

	exists, err := dbManager.Exists(uuid.MustParse(testIdentity.Uid))
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal(fmt.Errorf("dbManager.Exists returned true"))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// store identity
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

	// fetch identity
	tx, err = dbManager.StartTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}

	id, err := dbManager.FetchIdentity(tx, uuid.MustParse(testIdentity.Uid))
	if err != nil {
		t.Fatal(err)
	}

	err = dbManager.CloseTransaction(tx, Commit)
	if err != nil {
		t.Fatal(err)
	}

	if id.Uid != testIdentity.Uid ||
		id.AuthToken != testIdentity.AuthToken ||
		!bytes.Equal(id.PrivateKey, testIdentity.PrivateKey) ||
		!bytes.Equal(id.PublicKey, testIdentity.PublicKey) ||
		!bytes.Equal(id.Signature, testIdentity.Signature) {
		t.Fatal("fetched unexpected value")
	}

	// get individual attributes
	priv, err := dbManager.GetPrivateKey(uuid.MustParse(testIdentity.Uid))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := dbManager.GetPublicKey(uuid.MustParse(testIdentity.Uid))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := dbManager.GetAuthToken(uuid.MustParse(testIdentity.Uid))
	if err != nil {
		t.Fatal(err)
	}

	if auth != testIdentity.AuthToken ||
		!bytes.Equal(priv, testIdentity.PrivateKey) ||
		!bytes.Equal(pub, testIdentity.PublicKey) {
		t.Fatal("getter returned unexpected value")
	}

	err = cleanUp(dbManager)
	if err != nil {
		t.Fatal(err)
	}
}

func initDB() (*DatabaseManager, error) {
	conf := &config.Config{}
	err := conf.Load("../../", "config.json")
	if err != nil {
		return nil, fmt.Errorf("ERROR: unable to load configuration: %s", err)
	}

	return NewSqlDatabaseInfo(conf.PostgresDSN, TestTableName)
}

func initTestIdentity() *ent.Identity {
	priv, _ := base64.StdEncoding.DecodeString(TestPrivKey)
	pub, _ := base64.StdEncoding.DecodeString(TestPubKey)
	sig, _ := base64.StdEncoding.DecodeString(TestSignature)

	return &ent.Identity{
		Uid:        uuid.MustParse(TestUUID).String(),
		PrivateKey: priv,
		PublicKey:  pub,
		Signature:  sig,
		AuthToken:  TestAuthToken,
	}
}

func cleanUp(dbManager *DatabaseManager) error {
	deleteQuery := fmt.Sprintf("DELETE FROM %s WHERE uid = $1;", TestTableName)
	_, err := dbManager.db.Exec(deleteQuery, TestUUID)
	if err != nil {
		return err
	}

	dropTableQuery := fmt.Sprintf("DROP TABLE %s;", TestTableName)
	_, err = dbManager.db.Exec(dropTableQuery)
	if err != nil {
		return err
	}

	return nil
}
