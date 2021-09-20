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
	TestTableName  = "test_identity"
	TestUUID       = "2336c75d-a14a-47dd-80d9-3cbe9d560433"
	TestAuthToken  = "TEST_auth"
	TestPrivKey    = "Qkp+ZVAlEKCQNvI+OCbY7LKcQVW5iKfFMfzedTI3uG0="
	TestPubKey     = "bvXP3mQ42hXpcqo0ms7Lr1n6Q4L5CsS8HXk0mdXlsXLwYjd35jLlX3iHrXMgUH92N8ujbZ3h3TnLk8a0GikUbg=="
	TestSignature  = "XqfjRkM0g9swes9osaoptFCFau4Qq3jX+bv+SwPLkUARs8MRm6uRj3VCbvF3JZUlHAEuXmAn849vV9e71KGjDQ=="
	TestSignature2 = "Zr2GweEW6U/23BXBlR7MG7E0APYVtkhVSgtpUQ8e8EThtLEBjNIQcsX1B7bW3sbx8cBQQ9lBXFUPwaQ64X5HnQ=="
)

var (
	testIdentity = initTestIdentity()
)

func TestDatabaseManager(t *testing.T) {
	dbManager, err := initDB()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cleanUp(t, dbManager, cancel)

	// check not exists
	exists, err := dbManager.Exists(uuid.MustParse(testIdentity.Uid), 0)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Errorf("dbManager.Exists returned TRUE")
	}

	// store identity
	tx, err := dbManager.StartTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}

	err = dbManager.StoreNewIdentity(tx, testIdentity, 0)
	if err != nil {
		t.Fatal(err)
	}

	err = dbManager.CloseTransaction(tx, Commit)
	if err != nil {
		t.Fatal(err)
	}

	// check exists
	exists, err = dbManager.Exists(uuid.MustParse(testIdentity.Uid), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Errorf("dbManager.Exists returned FALSE")
	}

	// get attributes
	auth, err := dbManager.GetAuthToken(uuid.MustParse(testIdentity.Uid), 0)
	if err != nil {
		t.Fatal(err)
	}
	if auth != testIdentity.AuthToken {
		t.Error("GetAuthToken returned unexpected value")
	}

	pub, err := dbManager.GetPublicKey(uuid.MustParse(testIdentity.Uid), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, testIdentity.PublicKey) {
		t.Error("GetPublicKey returned unexpected value")
	}

	priv, err := dbManager.GetPrivateKey(uuid.MustParse(testIdentity.Uid), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv, testIdentity.PrivateKey) {
		t.Error("GetPrivateKey returned unexpected value")
	}

	// fetch identity
	tx, err = dbManager.StartTransactionWithLock(ctx, uuid.MustParse(testIdentity.Uid), 0)
	if err != nil {
		t.Fatal(err)
	}

	id, err := dbManager.FetchIdentity(tx, uuid.MustParse(testIdentity.Uid), 0)
	if err != nil {
		t.Fatal(err)
	}

	if id.Uid != testIdentity.Uid {
		t.Error("fetched unexpected uid value")
	}
	if id.AuthToken != testIdentity.AuthToken {
		t.Error("fetched unexpected auth token value")
	}
	if !bytes.Equal(id.PrivateKey, testIdentity.PrivateKey) {
		t.Error("fetched unexpected private key value")
	}
	if !bytes.Equal(id.PublicKey, testIdentity.PublicKey) {
		t.Error("fetched unexpected public key value")
	}
	if !bytes.Equal(id.Signature, testIdentity.Signature) {
		t.Error("fetched unexpected signature value")
	}

	// set signature
	sig2, _ := base64.StdEncoding.DecodeString(TestSignature2)
	err = dbManager.SetSignature(tx, uuid.MustParse(testIdentity.Uid), sig2, 0)
	if err != nil {
		t.Fatal(err)
	}

	err = dbManager.CloseTransaction(tx, Commit)
	if err != nil {
		t.Fatal(err)
	}

	// fetch identity to check signature
	tx, err = dbManager.StartTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}

	id, err = dbManager.FetchIdentity(tx, uuid.MustParse(testIdentity.Uid), 0)
	if err != nil {
		t.Fatal(err)
	}

	err = dbManager.CloseTransaction(tx, Commit)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(id.Signature, sig2) {
		t.Error("setting signature failed")
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

func cleanUp(t *testing.T, dbManager *DatabaseManager, cancel context.CancelFunc) {
	cancel()

	deleteQuery := fmt.Sprintf("DELETE FROM %s WHERE uid = $1;", TestTableName)
	_, err := dbManager.db.Exec(deleteQuery, TestUUID)
	if err != nil {
		t.Error(err)
	}

	dropTableQuery := fmt.Sprintf("DROP TABLE %s;", TestTableName)
	_, err = dbManager.db.Exec(dropTableQuery)
	if err != nil {
		t.Error(err)
	}
}
