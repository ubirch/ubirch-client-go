package handlers

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/rand"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	h "github.com/ubirch/ubirch-client-go/main/adapters/http_server"
	r "github.com/ubirch/ubirch-client-go/main/adapters/repository"
)

func TestIdentityHandler_InitIdentity(t *testing.T) {
	p, err := r.NewExtendedProtocol(&r.MockCtxMngr{}, conf)
	require.NoError(t, err)

	csrChan := make(chan []byte)

	idHandler := &IdentityHandler{
		Protocol:              p,
		SubmitKeyRegistration: MockSubmitKeyRegistration,
		SubmitCSR:             asynchMockSubmitCSR(csrChan),
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

	submittedCSR := <-csrChan
	assert.Equal(t, block.Bytes, submittedCSR)

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)

	csrPublicKey, err := p.EncodePublicKey(csr.PublicKey)
	require.NoError(t, err)

	initializedIdentity, err := p.LoadIdentity(testUuid)
	require.NoError(t, err)
	assert.Equal(t, csrPublicKey, initializedIdentity.PublicKey)

	pub, err := p.GetPublicKeyPEM(testUuid)
	require.NoError(t, err)
	assert.Equal(t, pub, initializedIdentity.PublicKey)

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
	assert.Equal(t, MockSubmitKeyRegistrationErr, err)

	initialized, err := p.IsInitialized(testUuid)
	require.NoError(t, err)
	assert.False(t, initialized)
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

	csrChan := make(chan []byte)

	idHandler := &IdentityHandler{
		Protocol:              p,
		SubmitKeyRegistration: MockSubmitKeyRegistration,
		SubmitCSR:             asynchMockSubmitCSR(csrChan),
		SubjectCountry:        "AA",
		SubjectOrganization:   "test GmbH",
	}

	_, err = idHandler.InitIdentity(testUuid, testAuth)
	require.NoError(t, err)
	<-csrChan

	csrPEM, err := idHandler.CreateCSR(testUuid)
	require.NoError(t, err)

	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Error("failed to decode PEM block containing CSR")
	}
	if len(rest) != 0 {
		t.Errorf("rest: %q", rest)
	}

	submittedCSR := <-csrChan
	assert.Equal(t, block.Bytes, submittedCSR)

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

func TestIdentityHandler_DeactivateKey_Unknown(t *testing.T) {
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

	err = idHandler.DeactivateKey(testUuid)
	assert.Equal(t, err, h.ErrUnknown)
}

func TestIdentityHandler_DeactivateKey_AlreadyDeactivated(t *testing.T) {
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

	err = idHandler.DeactivateKey(testUuid)
	require.Equal(t, h.ErrAlreadyDeactivated, err)
}

func TestIdentityHandler_DeactivateKey_BadKeyDeletion(t *testing.T) {
	p, err := r.NewExtendedProtocol(&r.MockCtxMngr{}, conf)
	require.NoError(t, err)

	idHandler := &IdentityHandler{
		Protocol:              p,
		SubmitKeyRegistration: MockSubmitKeyRegistration,
		RequestKeyDeletion:    MockSubmitKeyDeletionBad,
		SubmitCSR:             MockSubmitCSR,
		SubjectCountry:        "AA",
		SubjectOrganization:   "test GmbH",
	}

	_, err = idHandler.InitIdentity(testUuid, testAuth)
	require.NoError(t, err)

	err = idHandler.DeactivateKey(testUuid)
	require.Equal(t, MockSubmitKeyDeletionErr, err)
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

func TestIdentityHandler_ReactivateKey_Unknown(t *testing.T) {
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

	err = idHandler.ReactivateKey(testUuid)
	assert.Equal(t, err, h.ErrUnknown)
}

func TestIdentityHandler_ReactivateKey_AlreadyDeactivated(t *testing.T) {
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

	err = idHandler.ReactivateKey(testUuid)
	require.Equal(t, h.ErrAlreadyActivated, err)
}

func TestIdentityHandler_ReactivateKey_BadKeyRegistration(t *testing.T) {
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

	idHandler.SubmitKeyRegistration = MockSubmitKeyRegistrationBad

	err = idHandler.ReactivateKey(testUuid)
	require.Equal(t, MockSubmitKeyRegistrationErr, err)
}

func MockSubmitKeyRegistration(uuid.UUID, []byte) error {
	return nil
}

var MockSubmitKeyRegistrationErr = errors.New("MockSubmitKeyRegistrationBad")

func MockSubmitKeyRegistrationBad(uuid.UUID, []byte) error {
	return MockSubmitKeyRegistrationErr
}

func MockSubmitKeyDeletion(uuid.UUID, []byte) error {
	return nil
}

var MockSubmitKeyDeletionErr = errors.New("MockSubmitKeyDeletionBad")

func MockSubmitKeyDeletionBad(uuid.UUID, []byte) error {
	return MockSubmitKeyDeletionErr
}

func asynchMockSubmitCSR(csrChan chan []byte) func(uid uuid.UUID, csr []byte) error {
	return func(uid uuid.UUID, csr []byte) error {
		csrChan <- csr
		return nil
	}
}

func MockSubmitCSR(uuid.UUID, []byte) error {
	return nil
}

var MockSubmitCSRErr = errors.New("MockSubmitCSRBad")

func MockSubmitCSRBad(uuid.UUID, []byte) error {
	return MockSubmitCSRErr
}
