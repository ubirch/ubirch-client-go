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
		setExpectations               func(m *mock.Mock)
		tcChecks                      func(t *testing.T, resp h.HTTPResponse, m *mock.Mock)
	}{
		{
			name: "verification success",
			setExpectations: func(m *mock.Mock) {
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
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, getVerificationResponse(http.StatusOK, testHash[:], testVerificationUPP, testUuid, testPublicKey, ""), resp)
			},
		},
		{
			name: "load public key",
			setExpectations: func(m *mock.Mock) {
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
				m.On("PublicKeyPEMToBytes", testPublicKeyPEM).Return(testPublicKey, nil)
				m.On("Verify", testUuid, testVerificationUPP).Return(true, nil)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, getVerificationResponse(http.StatusOK, testHash[:], testVerificationUPP, testUuid, testPublicKey, ""), resp)
			},
		},
		{
			name: "not found",
			setExpectations: func(m *mock.Mock) {
				m.On("RequestHash", base64.StdEncoding.EncodeToString(testHash[:])).
					Return(h.HTTPResponse{StatusCode: http.StatusNotFound}, nil)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, http.StatusNotFound, resp.StatusCode)
			},
		},
		{
			name:                          "UPP from unknown identity",
			VerifyFromKnownIdentitiesOnly: true,
			setExpectations: func(m *mock.Mock) {
				m.On("RequestHash", base64.StdEncoding.EncodeToString(testHash[:])).
					Return(h.HTTPResponse{
						StatusCode: http.StatusOK,
						Header:     http.Header{"content-type": []string{h.JSONType}},
						Content:    testVerificationResp,
					}, nil)
				m.On("LoadPublicKey", testUuid).Return([]byte{}, r.ErrNotExist)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, getVerificationResponse(http.StatusForbidden, testHash[:], testVerificationUPP, testUuid, nil, ErrUnknownIdentity.Error()), resp)
			},
		},
		{
			name:                          "internal server error",
			VerifyFromKnownIdentitiesOnly: true,
			setExpectations: func(m *mock.Mock) {
				m.On("RequestHash", base64.StdEncoding.EncodeToString(testHash[:])).
					Return(h.HTTPResponse{
						StatusCode: http.StatusOK,
						Header:     http.Header{"content-type": []string{h.JSONType}},
						Content:    testVerificationResp,
					}, nil)
				m.On("LoadPublicKey", testUuid).Return([]byte{}, fmt.Errorf("some error"))
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, getVerificationResponse(http.StatusInternalServerError, testHash[:], testVerificationUPP, testUuid, nil, "some error"), resp)
			},
		},
		{
			name: "invalid signature",
			setExpectations: func(m *mock.Mock) {
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
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, getVerificationResponse(http.StatusForbidden, testHash[:], testVerificationUPP, testUuid, testPublicKey, "invalid UPP signature"), resp)
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			m := &mock.Mock{}
			m.Test(t)
			c.setExpectations(m)

			v := Verifier{
				VerifierProtocol:              &mockProto{mock: m},
				RequestHash:                   RequestHash(m),
				RequestPublicKeys:             RequestPublicKeys(m),
				VerifyFromKnownIdentitiesOnly: c.VerifyFromKnownIdentitiesOnly,
				VerificationTimeout:           time.Second,
			}

			resp := v.Verify(context.Background(), testHash[:])

			c.tcChecks(t, resp, m)
		})
	}
}