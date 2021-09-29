package mock

import (
	"context"
	"github.com/google/uuid"
	h "github.com/ubirch/ubirch-client-go/main/adapters/httphelper"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
)

type ExtendedProtocols interface {
	StartTransaction(ctx context.Context) (transactionCtx interface{}, err error)
	StartTransactionWithLock(ctx context.Context, uid uuid.UUID) (transactionCtx interface{}, err error)
	CloseTransaction(tx interface{}, commit bool) error
	Exists(uid uuid.UUID) (bool, error)
	StoreNewIdentity(tx interface{}, i *ent.Identity) error
	FetchIdentity(tx interface{}, uid uuid.UUID) (*ent.Identity, error)
	// FetchIdentityWithLock starts a transaction with lock and returns the locked identity
	FetchIdentityWithLock(ctx context.Context, uid uuid.UUID) (transactionCtx interface{}, identity *ent.Identity, err error)
	// SetSignature stores the signature and commits the transaction
	SetSignature(tx interface{}, uid uuid.UUID, signature []byte) error
	GetPrivateKey(uid uuid.UUID) ([]byte, error)
	GetPublicKey(uid uuid.UUID) (pubKeyPEM []byte, err error)
	GetAuthToken(uid uuid.UUID) (string, error)

	GenerateKey() (privKeyPEM []byte, err error)
	GetPublicKeyFromPrivateKey(privKeyPEM []byte) (pubKeyPEM []byte, err error)

	PublicKeyPEMToBytes(pubKeyPEM []byte) (pubKeyBytes []byte, err error)
	PublicKeyBytesToPEM(pubKeyBytes []byte) (pubKeyPEM []byte, err error)
	PrivateKeyBytesToPEM(privKeyBytes []byte) (privKeyPEM []byte, err error)

	EncodePrivateKey(priv interface{}) (pemEncoded []byte, err error)
	DecodePrivateKey(pemEncoded []byte) (priv interface{}, err error)
	EncodePublicKey(pub interface{}) (pemEncoded []byte, err error)
	DecodePublicKey(pemEncoded []byte) (pub interface{}, err error)

	GetSignedKeyRegistration(privKeyPEM []byte, uid uuid.UUID) ([]byte, error)
	GetCSR(privKeyPEM []byte, id uuid.UUID, subjectCountry string, subjectOrganization string) ([]byte, error)

	SignatureLength() int
	HashLength() int

	Sign(privKeyPEM []byte, value []byte) ([]byte, error)
	SignHash(privKeyPEM []byte, hash []byte) ([]byte, error)
	Verify(pubKeyPEM []byte, value []byte, signature []byte) (bool, error)

	RequestPublicKeys(id uuid.UUID) ([]ubirch.SignedKeyRegistration, error)
	IsKeyRegistered(id uuid.UUID, pubKey []byte) (bool, error)
	SubmitKeyRegistration(uid uuid.UUID, cert []byte, auth string) error
	SubmitCSR(uid uuid.UUID, csr []byte) error
	SendToAuthService(uid uuid.UUID, auth string, upp []byte) (h.HTTPResponse, error)
	Post(serviceURL string, data []byte, header map[string]string) (h.HTTPResponse, error)
}