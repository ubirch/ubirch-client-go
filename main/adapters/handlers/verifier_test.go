package handlers

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/ubirch/ubirch-client-go/main/ent"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	h "github.com/ubirch/ubirch-client-go/main/adapters/http_server"
	r "github.com/ubirch/ubirch-client-go/main/adapters/repository"
)

func (m *mockProto) LoadPublicKey(id uuid.UUID) (pubKeyPEM []byte, err error) {
	args := m.mock.MethodCalled("LoadPublicKey", id)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *mockProto) PublicKeyPEMToBytes(pubKeyPEM []byte) (pubKeyBytes []byte, err error) {
	args := m.mock.MethodCalled("PublicKeyPEMToBytes", pubKeyPEM)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *mockProto) SetPublicKeyBytes(id uuid.UUID, pubKeyBytes []byte) error {
	args := m.mock.MethodCalled("SetPublicKeyBytes", id, pubKeyBytes)
	return args.Error(0)
}

func (m *mockProto) Verify(id uuid.UUID, upp []byte) (bool, error) {
	args := m.mock.MethodCalled("Verify", id, upp)
	return args.Bool(0), args.Error(1)
}

func (m *mockProto) StoreExternalIdentity(ctx context.Context, extId ent.ExternalIdentity) error {
	defer func() { m.done <- true }()
	args := m.mock.MethodCalled("StoreExternalIdentity", ctx, extId)
	return args.Error(0)
}

func RequestHash(m *mock.Mock) func(hashBase64 string) (h.HTTPResponse, error) {
	return func(hashBase64 string) (h.HTTPResponse, error) {
		args := m.MethodCalled("RequestHash", hashBase64)
		return args.Get(0).(h.HTTPResponse), args.Error(1)
	}
}

func RequestPublicKeys(m *mock.Mock) func(id uuid.UUID) ([]ubirch.SignedKeyRegistration, error) {
	return func(id uuid.UUID) ([]ubirch.SignedKeyRegistration, error) {
		args := m.MethodCalled("RequestPublicKeys", id)
		return args.Get(0).([]ubirch.SignedKeyRegistration), args.Error(1)
	}
}

func TestVerifier_Verify(t *testing.T) {

	testCases := []struct {
		name                          string
		VerifyFromKnownIdentitiesOnly bool
		setMockBehavior               func(m *mock.Mock)
		tcChecks                      func(t *testing.T, resp h.HTTPResponse, m *mockProto)
	}{
		{
			name: "verification success",
			setMockBehavior: func(m *mock.Mock) {
				m.On("RequestHash", base64.StdEncoding.EncodeToString(testHash[:])).
					Return(h.HTTPResponse{
						StatusCode: http.StatusOK,
						Header:     http.Header{"content-type": []string{h.JSONType}},
						Content:    testVerificationResp,
					}, nil)
				m.On("LoadPublicKey", testUuid).Return(testPublicKeyPEM, nil)
				m.On("PublicKeyPEMToBytes", testPublicKeyPEM).Return(testPublicKey, nil)
				m.On("Verify", testUuid, testVerificationUPP).Return(true, nil)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mockProto) {
				m.mock.AssertExpectations(t)
				assert.Equal(t, getVerificationResponse(http.StatusOK, testHash[:], testVerificationUPP, testUuid, testPublicKey, ""), resp)
			},
		},
		{
			name: "load public key",
			setMockBehavior: func(m *mock.Mock) {
				m.On("RequestHash", base64.StdEncoding.EncodeToString(testHash[:])).
					Return(h.HTTPResponse{
						StatusCode: http.StatusOK,
						Header:     http.Header{"content-type": []string{h.JSONType}},
						Content:    testVerificationResp,
					}, nil)
				m.On("LoadPublicKey", testUuid).Return([]byte{}, r.ErrNotExist).Once()
				m.On("RequestPublicKeys", testUuid).Return(testKeyRegs, nil)
				m.On("SetPublicKeyBytes", testUuid, testPublicKey).Return(nil)
				m.On("LoadPublicKey", testUuid).Return(testPublicKeyPEM, nil)
				m.On("StoreExternalIdentity", context.TODO(), ent.ExternalIdentity{
					Uid:       testUuid,
					PublicKey: testPublicKeyPEM,
				}).Return(nil)
				m.On("PublicKeyPEMToBytes", testPublicKeyPEM).Return(testPublicKey, nil)
				m.On("Verify", testUuid, testVerificationUPP).Return(true, nil)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mockProto) {
				<-m.done
				m.mock.AssertExpectations(t)
				assert.Equal(t, getVerificationResponse(http.StatusOK, testHash[:], testVerificationUPP, testUuid, testPublicKey, ""), resp)
			},
		},
		{
			name: "not found",
			setMockBehavior: func(m *mock.Mock) {
				m.On("RequestHash", base64.StdEncoding.EncodeToString(testHash[:])).
					Return(h.HTTPResponse{StatusCode: http.StatusNotFound}, nil)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mockProto) {
				m.mock.AssertExpectations(t)
				assert.Equal(t, http.StatusNotFound, resp.StatusCode)
			},
		},
		{
			name:                          "UPP from unknown identity",
			VerifyFromKnownIdentitiesOnly: true,
			setMockBehavior: func(m *mock.Mock) {
				m.On("RequestHash", base64.StdEncoding.EncodeToString(testHash[:])).
					Return(h.HTTPResponse{
						StatusCode: http.StatusOK,
						Header:     http.Header{"content-type": []string{h.JSONType}},
						Content:    testVerificationResp,
					}, nil)
				m.On("LoadPublicKey", testUuid).Return([]byte{}, r.ErrNotExist)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mockProto) {
				m.mock.AssertExpectations(t)
				assert.Equal(t, getVerificationResponse(http.StatusForbidden, testHash[:], testVerificationUPP, testUuid, nil, ErrUnknownIdentity.Error()), resp)
			},
		},
		{
			name: "internal server error",
			setMockBehavior: func(m *mock.Mock) {
				m.On("RequestHash", base64.StdEncoding.EncodeToString(testHash[:])).
					Return(h.HTTPResponse{
						StatusCode: http.StatusOK,
						Header:     http.Header{"content-type": []string{h.JSONType}},
						Content:    testVerificationResp,
					}, nil)
				m.On("LoadPublicKey", testUuid).Return([]byte{}, fmt.Errorf("some error"))
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mockProto) {
				m.mock.AssertExpectations(t)
				assert.Equal(t, getVerificationResponse(http.StatusInternalServerError, testHash[:], testVerificationUPP, testUuid, nil, "some error"), resp)
			},
		},
		{
			name: "invalid signature",
			setMockBehavior: func(m *mock.Mock) {
				m.On("RequestHash", base64.StdEncoding.EncodeToString(testHash[:])).
					Return(h.HTTPResponse{
						StatusCode: http.StatusOK,
						Header:     http.Header{"content-type": []string{h.JSONType}},
						Content:    testVerificationResp,
					}, nil)
				m.On("LoadPublicKey", testUuid).Return(testPublicKeyPEM, nil)
				m.On("PublicKeyPEMToBytes", testPublicKeyPEM).Return(testPublicKey, nil)
				m.On("Verify", testUuid, testVerificationUPP).Return(false, nil)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mockProto) {
				m.mock.AssertExpectations(t)
				assert.Equal(t, getVerificationResponse(http.StatusForbidden, testHash[:], testVerificationUPP, testUuid, testPublicKey, "invalid UPP signature"), resp)
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			m := &mockProto{mock: &mock.Mock{}, done: make(chan bool)}
			m.mock.Test(t)
			c.setMockBehavior(m.mock)

			v := Verifier{
				VerifierProtocol:              m,
				RequestHash:                   RequestHash(m.mock),
				RequestPublicKeys:             RequestPublicKeys(m.mock),
				VerifyFromKnownIdentitiesOnly: c.VerifyFromKnownIdentitiesOnly,
				VerificationTimeout:           time.Second,
			}

			resp := v.Verify(context.Background(), testHash[:])

			c.tcChecks(t, resp, m)
		})
	}
}

func TestVerifier_VerifyOffline(t *testing.T) {

	testCases := []struct {
		name            string
		upp             []byte
		setMockBehavior func(m *mock.Mock)
		tcChecks        func(t *testing.T, resp h.HTTPResponse, m *mock.Mock)
	}{
		{
			name: "verification success",
			upp:  testVerificationUPP,
			setMockBehavior: func(m *mock.Mock) {
				m.On("LoadPublicKey", testUuid).Return(testPublicKeyPEM, nil)
				m.On("PublicKeyPEMToBytes", testPublicKeyPEM).Return(testPublicKey, nil)
				m.On("Verify", testUuid, testVerificationUPP).Return(true, nil)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, getVerificationResponse(http.StatusOK, testHash[:], testVerificationUPP, testUuid, testPublicKey, ""), resp)
			},
		},
		{
			name: "UPP from unknown identity",
			upp:  testVerificationUPP,
			setMockBehavior: func(m *mock.Mock) {
				m.On("LoadPublicKey", testUuid).Return([]byte{}, r.ErrNotExist)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, getVerificationResponse(http.StatusNotFound, testHash[:], testVerificationUPP, testUuid, nil, ErrUnknownIdentity.Error()), resp)
			},
		},
		{
			name:            "invalid UPP",
			upp:             testVerificationUPP[1:],
			setMockBehavior: func(m *mock.Mock) {},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, getVerificationResponse(http.StatusBadRequest, testHash[:], testVerificationUPP[1:], uuid.Nil, nil, ErrInvalidUPP.Error()), resp)
			},
		},
		{
			name: "internal server error",
			upp:  testVerificationUPP,
			setMockBehavior: func(m *mock.Mock) {
				m.On("LoadPublicKey", testUuid).Return(testPublicKeyPEM, nil)
				m.On("PublicKeyPEMToBytes", testPublicKeyPEM).Return(testPublicKey, nil)
				m.On("Verify", testUuid, testVerificationUPP).Return(false, fmt.Errorf("some error"))
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, getVerificationResponse(http.StatusInternalServerError, testHash[:], testVerificationUPP, testUuid, testPublicKey, "unable to verify UPP: some error"), resp)
			},
		},
		{
			name: "invalid signature",
			upp:  testVerificationUPP,
			setMockBehavior: func(m *mock.Mock) {
				m.On("LoadPublicKey", testUuid).Return(testPublicKeyPEM, nil)
				m.On("PublicKeyPEMToBytes", testPublicKeyPEM).Return(testPublicKey, nil)
				m.On("Verify", testUuid, testVerificationUPP).Return(false, nil)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, getVerificationResponse(http.StatusForbidden, testHash[:], testVerificationUPP, testUuid, testPublicKey, "invalid UPP signature"), resp)
			},
		},
		{
			name: "hash mismatch",
			upp:  testSignedUPP,
			setMockBehavior: func(m *mock.Mock) {
				m.On("LoadPublicKey", testUuid).Return(testPublicKeyPEM, nil)
				m.On("PublicKeyPEMToBytes", testPublicKeyPEM).Return(testPublicKey, nil)
				m.On("Verify", testUuid, testSignedUPP).Return(true, nil)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			m := &mock.Mock{}
			m.Test(t)
			c.setMockBehavior(m)

			v := Verifier{
				VerifierProtocol: &mockProto{mock: m},
			}

			resp := v.VerifyOffline(c.upp, testHash[:])

			c.tcChecks(t, resp, m)
		})
	}
}
