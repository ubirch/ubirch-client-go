package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	h "github.com/ubirch/ubirch-client-go/main/adapters/http_server"
	r "github.com/ubirch/ubirch-client-go/main/adapters/repository"
)

type mockProto struct {
	mock *mock.Mock
	done chan bool
}

func (m *mockProto) LoadActiveFlag(uid uuid.UUID) (bool, error) {
	args := m.mock.MethodCalled("LoadActiveFlag", uid)
	return args.Bool(0), args.Error(1)
}

func (m *mockProto) StartTransaction(ctx context.Context) (r.TransactionCtx, error) {
	args := m.mock.MethodCalled("StartTransaction", ctx)
	return args.Get(0).(*mockTx), args.Error(1)
}

func (m *mockProto) LoadSignatureForUpdate(tx r.TransactionCtx, uid uuid.UUID) ([]byte, error) {
	args := m.mock.MethodCalled("LoadSignatureForUpdate", tx, uid)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *mockProto) StoreSignature(tx r.TransactionCtx, uid uuid.UUID, sig []byte) error {
	args := m.mock.MethodCalled("StoreSignature", tx, uid, sig)
	return args.Error(0)
}

func (m *mockProto) GetPublicKeyBytes(uid uuid.UUID) ([]byte, error) {
	args := m.mock.MethodCalled("GetPublicKeyBytes", uid)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *mockProto) SignatureLength() int {
	args := m.mock.MethodCalled("SignatureLength")
	return args.Int(0)
}

func (m *mockProto) Sign(upp ubirch.UPP) ([]byte, error) {
	args := m.mock.MethodCalled("Sign", upp)
	return args.Get(0).([]byte), args.Error(1)
}

type mockTx struct{}

func (m *mockTx) Commit() error   { return nil }
func (m *mockTx) Rollback() error { return nil }

func sendToAuthService(m *mock.Mock) func(uid uuid.UUID, auth string, upp []byte) (h.HTTPResponse, error) {
	return func(uid uuid.UUID, auth string, upp []byte) (h.HTTPResponse, error) {
		args := m.MethodCalled("sendToAuthService", uid, auth, upp)
		return args.Get(0).(h.HTTPResponse), args.Error(1)
	}
}

func TestSigner_Sign(t *testing.T) {

	testCases := []struct {
		name            string
		msg             h.HTTPRequest
		setMockBehavior func(m *mock.Mock)
		tcChecks        func(t *testing.T, resp h.HTTPResponse, m *mock.Mock)
	}{
		{
			name: "chain online",
			msg: h.HTTPRequest{
				Ctx:       context.Background(),
				ID:        testUuid,
				Auth:      testAuth,
				Hash:      testHash,
				Operation: h.ChainHash,
				Offline:   false,
			},
			setMockBehavior: func(m *mock.Mock) {
				m.On("LoadActiveFlag", testUuid).Return(true, nil)
				m.On("StartTransaction", mock.AnythingOfType("*context.emptyCtx")).Return(&mockTx{}, nil)
				m.On("LoadSignatureForUpdate", &mockTx{}, testUuid).Return(testSignature, nil)
				m.On("Sign", &ubirch.ChainedUPP{
					Version:       ubirch.Chained,
					Uuid:          testUuid,
					PrevSignature: testSignature,
					Hint:          ubirch.Binary,
					Payload:       testHash[:],
				}).Return(testChainedUPP, nil)
				m.On("GetPublicKeyBytes", testUuid).Return(testPublicKey, nil)
				m.On("sendToAuthService", testUuid, testAuth, testChainedUPP).Return(testBckndResp, nil)
				m.On("SignatureLength").Return(64)
				m.On("StoreSignature", &mockTx{}, testUuid, testChainedUPP[len(testChainedUPP)-64:]).Return(nil)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, getSigningResponse(http.StatusOK, testHash[:], testChainedUPP, testPublicKey, &testBckndResp, testRequestID), resp)
			},
		},
		{
			name: "chain offline",
			msg: h.HTTPRequest{
				Ctx:       context.Background(),
				ID:        testUuid,
				Auth:      testAuth,
				Hash:      testHash,
				Operation: h.ChainHash,
				Offline:   true,
			},
			setMockBehavior: func(m *mock.Mock) {
				m.On("LoadActiveFlag", testUuid).Return(true, nil)
				m.On("StartTransaction", mock.AnythingOfType("*context.emptyCtx")).Return(&mockTx{}, nil)
				m.On("LoadSignatureForUpdate", &mockTx{}, testUuid).Return(testSignature, nil)
				m.On("Sign", &ubirch.ChainedUPP{
					Version:       ubirch.Chained,
					Uuid:          testUuid,
					PrevSignature: testSignature,
					Hint:          ubirch.Binary,
					Payload:       testHash[:],
				}).Return(testChainedUPP, nil)
				m.On("GetPublicKeyBytes", testUuid).Return(testPublicKey, nil)
				m.On("SignatureLength").Return(64)
				m.On("StoreSignature", &mockTx{}, testUuid, testChainedUPP[len(testChainedUPP)-64:]).Return(nil)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, getSigningResponse(http.StatusOK, testHash[:], testChainedUPP, testPublicKey, nil, ""), resp)
			},
		},
		{
			name: "anchor online",
			msg: h.HTTPRequest{
				Ctx:       context.Background(),
				ID:        testUuid,
				Auth:      testAuth,
				Hash:      testHash,
				Operation: h.AnchorHash,
				Offline:   false,
			},
			setMockBehavior: func(m *mock.Mock) {
				m.On("LoadActiveFlag", testUuid).Return(true, nil)
				m.On("Sign", &ubirch.SignedUPP{
					Version: ubirch.Signed,
					Uuid:    testUuid,
					Hint:    ubirch.Binary,
					Payload: testHash[:],
				}).Return(testSignedUPP, nil)
				m.On("GetPublicKeyBytes", testUuid).Return(testPublicKey, nil)
				m.On("sendToAuthService", testUuid, testAuth, testSignedUPP).Return(testBckndResp, nil)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, getSigningResponse(http.StatusOK, testHash[:], testSignedUPP, testPublicKey, &testBckndResp, testRequestID), resp)
			},
		},
		{
			name: "anchor offline",
			msg: h.HTTPRequest{
				Ctx:       context.Background(),
				ID:        testUuid,
				Auth:      testAuth,
				Hash:      testHash,
				Operation: h.AnchorHash,
				Offline:   true,
			},
			setMockBehavior: func(m *mock.Mock) {
				m.On("LoadActiveFlag", testUuid).Return(true, nil)
				m.On("Sign", &ubirch.SignedUPP{
					Version: ubirch.Signed,
					Uuid:    testUuid,
					Hint:    ubirch.Binary,
					Payload: testHash[:],
				}).Return(testSignedUPP, nil)
				m.On("GetPublicKeyBytes", testUuid).Return(testPublicKey, nil)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, getSigningResponse(http.StatusOK, testHash[:], testSignedUPP, testPublicKey, nil, ""), resp)
			},
		},
		{
			name: "disable",
			msg: h.HTTPRequest{
				Ctx:       context.Background(),
				ID:        testUuid,
				Auth:      testAuth,
				Hash:      testHash,
				Operation: h.DisableHash,
			},
			setMockBehavior: func(m *mock.Mock) {
				m.On("LoadActiveFlag", testUuid).Return(true, nil)
				m.On("Sign", &ubirch.SignedUPP{
					Version: ubirch.Signed,
					Uuid:    testUuid,
					Hint:    ubirch.Disable,
					Payload: testHash[:],
				}).Return(testSignedUPP, nil)
				m.On("GetPublicKeyBytes", testUuid).Return(testPublicKey, nil)
				m.On("sendToAuthService", testUuid, testAuth, testSignedUPP).Return(testBckndResp, nil)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, getSigningResponse(http.StatusOK, testHash[:], testSignedUPP, testPublicKey, &testBckndResp, testRequestID), resp)
			},
		},
		{
			name: "enable",
			msg: h.HTTPRequest{
				Ctx:       context.Background(),
				ID:        testUuid,
				Auth:      testAuth,
				Hash:      testHash,
				Operation: h.EnableHash,
			},
			setMockBehavior: func(m *mock.Mock) {
				m.On("LoadActiveFlag", testUuid).Return(true, nil)
				m.On("Sign", &ubirch.SignedUPP{
					Version: ubirch.Signed,
					Uuid:    testUuid,
					Hint:    ubirch.Enable,
					Payload: testHash[:],
				}).Return(testSignedUPP, nil)
				m.On("GetPublicKeyBytes", testUuid).Return(testPublicKey, nil)
				m.On("sendToAuthService", testUuid, testAuth, testSignedUPP).Return(testBckndResp, nil)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, getSigningResponse(http.StatusOK, testHash[:], testSignedUPP, testPublicKey, &testBckndResp, testRequestID), resp)
			},
		},
		{
			name: "delete",
			msg: h.HTTPRequest{
				Ctx:       context.Background(),
				ID:        testUuid,
				Auth:      testAuth,
				Hash:      testHash,
				Operation: h.DeleteHash,
			},
			setMockBehavior: func(m *mock.Mock) {
				m.On("LoadActiveFlag", testUuid).Return(true, nil)
				m.On("Sign", &ubirch.SignedUPP{
					Version: ubirch.Signed,
					Uuid:    testUuid,
					Hint:    ubirch.Delete,
					Payload: testHash[:],
				}).Return(testSignedUPP, nil)
				m.On("GetPublicKeyBytes", testUuid).Return(testPublicKey, nil)
				m.On("sendToAuthService", testUuid, testAuth, testSignedUPP).Return(testBckndResp, nil)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, getSigningResponse(http.StatusOK, testHash[:], testSignedUPP, testPublicKey, &testBckndResp, testRequestID), resp)
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			m := &mock.Mock{}
			m.Test(t)
			c.setMockBehavior(m)

			s := Signer{
				SignerProtocol:    &mockProto{mock: m},
				SendToAuthService: sendToAuthService(m),
			}

			resp := s.Sign(c.msg)

			c.tcChecks(t, resp, m)
		})
	}
}
