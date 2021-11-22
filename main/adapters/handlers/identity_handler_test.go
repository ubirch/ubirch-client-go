package handlers

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/rand"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	h "github.com/ubirch/ubirch-client-go/main/adapters/http_server"
	r "github.com/ubirch/ubirch-client-go/main/adapters/repository"
)

var (
	testUuid      = uuid.New()
	testAuth      = "123456"
	testSecret, _ = base64.StdEncoding.DecodeString("ZQJt1OC9+4OZtgZLLT9mX25BbrZdxtOQBjK4GyRF2fQ=")
	conf          = &config.Config{SecretBytes32: testSecret}
)

func TestIdentityHandler_InitIdentity(t *testing.T) {
	p, err := r.NewExtendedProtocol(&r.MockCtxMngr{}, conf)
	require.NoError(t, err)

	idHandler := &IdentityHandler{
		Protocol:              p,
		SubmitKeyRegistration: MockSubmitKeyRegistration,
		SubmitCSR:             MockSubmitCSR,
		SubjectCountry:        "AA",
		SubjectOrganization:   "test GmbH",
	}

	csrPEM, err := idHandler.InitIdentity(testUuid, testAuth)
	require.NoError(t, err)

	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Error("failed to decode PEM block containing CSR")
	}
	if len(rest) != 0 {
		t.Errorf("rest: %q", rest)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	assert.NoError(t, err)

	initializedIdentity, err := p.LoadIdentity(testUuid)
	require.NoError(t, err)

	pub, err := p.GetPublicKeyPEM(testUuid)
	require.NoError(t, err)
	assert.Equal(t, pub, initializedIdentity.PublicKey)

	csrPublicKey, err := p.EncodePublicKey(csr.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, csrPublicKey, initializedIdentity.PublicKey)

	found, ok, err := p.CheckAuth(context.Background(), testUuid, testAuth)
	require.NoError(t, err)
	assert.True(t, found)
	assert.True(t, ok)

	assert.Equal(t, make([]byte, p.SignatureLength()), initializedIdentity.Signature)

	hash := make([]byte, p.HashLength())
	rand.Read(hash)

	upp, err := p.Sign(
		&ubirch.SignedUPP{
			Version: ubirch.Signed,
			Uuid:    testUuid,
			Hint:    0x00,
			Payload: hash,
		})
	require.NoError(t, err)

	verified, err := p.Verify(testUuid, upp)
	require.NoError(t, err)
	assert.True(t, verified)
}

func TestIdentityHandler_InitIdentityBad_ErrAlreadyInitialized(t *testing.T) {
	p, err := r.NewExtendedProtocol(&r.MockCtxMngr{}, conf)
	require.NoError(t, err)

	idHandler := &IdentityHandler{
		Protocol:              p,
		SubmitKeyRegistration: MockSubmitKeyRegistration,
		SubmitCSR:             MockSubmitCSR,
		SubjectCountry:        "AA",
		SubjectOrganization:   "test GmbH",
	}

	_, err = idHandler.InitIdentity(testUuid, testAuth)
	require.NoError(t, err)

	_, err = idHandler.InitIdentity(testUuid, testAuth)
	assert.Equal(t, h.ErrAlreadyInitialized, err)
}

func TestIdentityHandler_InitIdentity_BadRegistration(t *testing.T) {
	p, err := r.NewExtendedProtocol(&r.MockCtxMngr{}, conf)
	require.NoError(t, err)

	idHandler := &IdentityHandler{
		Protocol:              p,
		SubmitKeyRegistration: MockSubmitKeyRegistrationBad,
		SubmitCSR:             MockSubmitCSR,
		SubjectCountry:        "AA",
		SubjectOrganization:   "test GmbH",
	}

	_, err = idHandler.InitIdentity(testUuid, testAuth)
	assert.Error(t, err)

	_, err = p.LoadIdentity(testUuid)
	assert.Equal(t, r.ErrNotExist, err)
}

func TestIdentityHandler_InitIdentity_BadSubmitCSR(t *testing.T) {
	p, err := r.NewExtendedProtocol(&r.MockCtxMngr{}, conf)
	require.NoError(t, err)

	idHandler := &IdentityHandler{
		Protocol:              p,
		SubmitKeyRegistration: MockSubmitKeyRegistration,
		SubmitCSR:             MockSubmitCSRBad,
		SubjectCountry:        "AA",
		SubjectOrganization:   "test GmbH",
	}

	_, err = idHandler.InitIdentity(testUuid, testAuth)
	assert.NoError(t, err)

	_, err = p.LoadIdentity(testUuid)
	assert.NoError(t, err)
}

func TestIdentityHandler_CreateCSR(t *testing.T) {
	p, err := r.NewExtendedProtocol(&r.MockCtxMngr{}, conf)
	require.NoError(t, err)

	idHandler := &IdentityHandler{
		Protocol:              p,
		SubmitKeyRegistration: MockSubmitKeyRegistration,
		SubmitCSR:             MockSubmitCSR,
		SubjectCountry:        "AA",
		SubjectOrganization:   "test GmbH",
	}

	_, err = idHandler.InitIdentity(testUuid, testAuth)
	require.NoError(t, err)

	csrPEM, err := idHandler.CreateCSR(testUuid)
	require.NoError(t, err)

	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Error("failed to decode PEM block containing CSR")
	}
	if len(rest) != 0 {
		t.Errorf("rest: %q", rest)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	assert.NoError(t, err)

	initializedIdentity, err := p.LoadIdentity(testUuid)
	require.NoError(t, err)

	csrPublicKey, err := p.EncodePublicKey(csr.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, csrPublicKey, initializedIdentity.PublicKey)
}

func TestIdentityHandler_CreateCSR_Unknown(t *testing.T) {
	p, err := r.NewExtendedProtocol(&r.MockCtxMngr{}, conf)
	require.NoError(t, err)

	idHandler := &IdentityHandler{
		Protocol:              p,
		SubmitKeyRegistration: MockSubmitKeyRegistration,
		SubmitCSR:             MockSubmitCSR,
		SubjectCountry:        "AA",
		SubjectOrganization:   "test GmbH",
	}

	_, err = idHandler.CreateCSR(testUuid)
	assert.Equal(t, h.ErrUnknown, err)
}

func TestIdentityHandler_InitIdentities(t *testing.T) {
	testUuid2 := uuid.New()
	testAuth2 := "456789"

	p, err := r.NewExtendedProtocol(&r.MockCtxMngr{}, conf)
	require.NoError(t, err)

	idHandler := &IdentityHandler{
		Protocol:              p,
		SubmitKeyRegistration: MockSubmitKeyRegistration,
		SubmitCSR:             MockSubmitCSR,
		SubjectCountry:        "AA",
		SubjectOrganization:   "test GmbH",
	}

	identities := map[string]string{
		testUuid.String():  testAuth,
		testUuid2.String(): testAuth2,
	}

	err = idHandler.InitIdentities(identities)
	require.NoError(t, err)

	err = idHandler.InitIdentities(map[string]string{
		testUuid2.String(): testAuth2,
	})
	require.NoError(t, err)

	err = idHandler.InitIdentities(map[string]string{
		"123456": "456789",
	})
	require.Error(t, err)
}

func TestIdentityHandler_DeactivateKey(t *testing.T) {
	p, err := r.NewExtendedProtocol(&r.MockCtxMngr{}, conf)
	require.NoError(t, err)

	idHandler := &IdentityHandler{
		Protocol:              p,
		SubmitKeyRegistration: MockSubmitKeyRegistration,
		RequestKeyDeletion:    MockSubmitKeyDeletion,
		SubmitCSR:             MockSubmitCSR,
		SubjectCountry:        "AA",
		SubjectOrganization:   "test GmbH",
	}

	_, err = idHandler.InitIdentity(testUuid, testAuth)
	require.NoError(t, err)

	err = idHandler.DeactivateKey(testUuid)
	require.NoError(t, err)

	active, err := idHandler.Protocol.LoadActiveFlag(testUuid)
	require.NoError(t, err)
	assert.False(t, active)
}

func TestIdentityHandler_ReactivateKey(t *testing.T) {
	p, err := r.NewExtendedProtocol(&r.MockCtxMngr{}, conf)
	require.NoError(t, err)

	idHandler := &IdentityHandler{
		Protocol:              p,
		SubmitKeyRegistration: MockSubmitKeyRegistration,
		RequestKeyDeletion:    MockSubmitKeyDeletion,
		SubmitCSR:             MockSubmitCSR,
		SubjectCountry:        "AA",
		SubjectOrganization:   "test GmbH",
	}

	_, err = idHandler.InitIdentity(testUuid, testAuth)
	require.NoError(t, err)

	err = idHandler.DeactivateKey(testUuid)
	require.NoError(t, err)

	active, err := idHandler.Protocol.LoadActiveFlag(testUuid)
	require.NoError(t, err)
	assert.False(t, active)

	err = idHandler.ReactivateKey(testUuid)
	require.NoError(t, err)

	active, err = idHandler.Protocol.LoadActiveFlag(testUuid)
	require.NoError(t, err)
	assert.True(t, active)
}

func MockSubmitKeyRegistration(uuid.UUID, []byte) error {
	return nil
}

func MockSubmitKeyRegistrationBad(uuid.UUID, []byte) error {
	return fmt.Errorf("fail")
}

func MockSubmitKeyDeletion(uuid.UUID, []byte) error {
	return nil
}

func MockSubmitKeyDeletionBad(uuid.UUID, []byte) error {
	return fmt.Errorf("fail")
}

func MockSubmitCSR(uuid.UUID, []byte) error {
	return nil
}

func MockSubmitCSRBad(uuid.UUID, []byte) error {
	return fmt.Errorf("fail")
}
