package handlers

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	h "github.com/ubirch/ubirch-client-go/main/adapters/http_server"
	r "github.com/ubirch/ubirch-client-go/main/adapters/repository"
)

var (
	testHash         = h.Sha256Sum{0x80, 0xc9, 0x83, 0xc2, 0xfa, 0x61, 0x75, 0x1b, 0x2f, 0x78, 0x42, 0xa3, 0xa3, 0x39, 0x34, 0xfc, 0xbe, 0xd1, 0xc4, 0x3a, 0xa2, 0x5c, 0xa3, 0xb6, 0x39, 0x5c, 0x12, 0xf5, 0x53, 0xe2, 0xf0, 0x5e}
	testSignature    = []byte{0xb6, 0x2b, 0xc0, 0x1a, 0xc9, 0xe5, 0xb1, 0xd8, 0x97, 0x73, 0x6f, 0xf9, 0x87, 0x7b, 0x43, 0x75, 0x3c, 0xb7, 0xbd, 0x57, 0xb1, 0xb0, 0x47, 0x7e, 0x87, 0xdc, 0x47, 0x34, 0x20, 0x25, 0x94, 0xf5, 0x4a, 0xfb, 0x78, 0x28, 0x3e, 0xf8, 0x9, 0xbf, 0x9f, 0x72, 0xbc, 0x5d, 0x55, 0x6f, 0x66, 0x5b, 0xb1, 0xff, 0x11, 0x7e, 0x59, 0x22, 0x1d, 0xe3, 0xea, 0x3a, 0xb3, 0x57, 0x3e, 0x5f, 0xe9, 0xd0}
	testPublicKey, _ = base64.StdEncoding.DecodeString("BQvX+52fPRd9nxwYDR7keuZT1kYZuZifonYD+hjjdMdxT5biLGHIF5saEClFHVzG/D6pDZswOfYrNuE9osN/Pg==")
	testUPP          = []byte{0x96, 0x23, 0xc4, 0x10, 0x7e, 0x41, 0xc4, 0x21, 0xac, 0xad, 0x46, 0xe5, 0x95, 0xf3, 0x20, 0x70, 0xcf, 0x78, 0x29, 0x2b, 0xc4, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc4, 0x20, 0x95, 0xd5, 0x80, 0x47, 0xc6, 0x72, 0xe, 0xb, 0xaa, 0x1e, 0xbf, 0xc5, 0xcc, 0xf4, 0xe7, 0xa4, 0x66, 0x68, 0xc2, 0x36, 0x32, 0x31, 0x4d, 0x6e, 0x2a, 0x82, 0xfb, 0x47, 0x7d, 0xa2, 0xc4, 0x32, 0xc4, 0x40, 0x1e, 0xa6, 0x34, 0x30, 0x38, 0x64, 0xa2, 0x28, 0xf4, 0x86, 0x5, 0x44, 0x23, 0xb9, 0xc5, 0x61, 0x70, 0x1b, 0x5c, 0x3c, 0x32, 0x96, 0xb2, 0x9a, 0xdc, 0x88, 0xd9, 0xd2, 0xde, 0x9, 0x43, 0xfd, 0xeb, 0xf2, 0xfc, 0x3c, 0xa3, 0x12, 0x94, 0xbd, 0x74, 0xc3, 0x2d, 0xac, 0xfe, 0x1e, 0x36, 0xa2, 0xb0, 0x3e, 0x9b, 0x1, 0xb8, 0x5e, 0xa3, 0x9a, 0x38, 0xfb, 0xf4, 0x2c, 0xd1, 0xa4, 0xf3, 0x3a}
	testBckndRespUPP = []byte{0x96, 0x23, 0xc4, 0x10, 0x10, 0xb2, 0xe1, 0xa4, 0x56, 0xb3, 0x4f, 0xff, 0x9a, 0xda, 0xcc, 0x8c, 0x20, 0xf9, 0x30, 0x16, 0xc4, 0x40, 0x1e, 0xa6, 0x34, 0x30, 0x38, 0x64, 0xa2, 0x28, 0xf4, 0x86, 0x5, 0x44, 0x23, 0xb9, 0xc5, 0x61, 0x70, 0x1b, 0x5c, 0x3c, 0x32, 0x96, 0xb2, 0x9a, 0xdc, 0x88, 0xd9, 0xd2, 0xde, 0x9, 0x43, 0xfd, 0xeb, 0xf2, 0xfc, 0x3c, 0xa3, 0x12, 0x94, 0xbd, 0x74, 0xc3, 0x2d, 0xac, 0xfe, 0x1e, 0x36, 0xa2, 0xb0, 0x3e, 0x9b, 0x1, 0xb8, 0x5e, 0xa3, 0x9a, 0x38, 0xfb, 0xf4, 0x2c, 0xd1, 0xa4, 0xf3, 0x3a, 0x0, 0xc4, 0x20, 0x2e, 0x33, 0x60, 0x93, 0x4f, 0xd0, 0x4e, 0x61, 0x8f, 0x49, 0xcb, 0x19, 0x3c, 0xbb, 0x42, 0xf8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc4, 0x40, 0x99, 0xc9, 0xd9, 0x2e, 0xd, 0xf1, 0x19, 0xdf, 0x11, 0x3, 0xe6, 0x2c, 0xe4, 0x25, 0x60, 0xd8, 0x2f, 0x3f, 0x5b, 0x3, 0x6a, 0x38, 0x9f, 0xc7, 0x1e, 0x23, 0xf3, 0x54, 0x59, 0x6c, 0x51, 0xb0, 0x3, 0x44, 0x27, 0xad, 0xc1, 0x6a, 0x9c, 0xf9, 0x12, 0x2b, 0x1d, 0x21, 0xfc, 0xe5, 0x2a, 0xf6, 0xaf, 0x63, 0x98, 0xff, 0xd8, 0xdc, 0x4b, 0xe3, 0x10, 0x31, 0x12, 0x4e, 0xc, 0x8e, 0x76, 0x52}
	testRequestID    = "2e336093-4fd0-4e61-8f49-cb193cbb42f8"
	testBckndResp    = h.HTTPResponse{
		StatusCode: http.StatusOK,
		Header:     http.Header{"test": []string{"header"}},
		Content:    testBckndRespUPP,
	}
)

type mockProto struct {
	mock *mock.Mock
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
		setExpectations func(m *mock.Mock)
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
			setExpectations: func(m *mock.Mock) {
				m.On("LoadActiveFlag", testUuid).Return(true, nil)
				m.On("StartTransaction", mock.AnythingOfType("*context.emptyCtx")).Return(&mockTx{}, nil)
				m.On("LoadSignatureForUpdate", &mockTx{}, testUuid).Return(testSignature, nil)
				m.On("Sign", &ubirch.ChainedUPP{
					Version:       ubirch.Chained,
					Uuid:          testUuid,
					PrevSignature: testSignature,
					Hint:          ubirch.Binary,
					Payload:       testHash[:],
				}).Return(testUPP, nil)
				m.On("GetPublicKeyBytes", testUuid).Return(testPublicKey, nil)
				m.On("sendToAuthService", testUuid, testAuth, testUPP).Return(testBckndResp, nil)
				m.On("SignatureLength").Return(64)
				m.On("StoreSignature", &mockTx{}, testUuid, testUPP[len(testUPP)-64:]).Return(nil)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, getSigningResponse(http.StatusOK, testHash[:], testUPP, testPublicKey, testBckndResp, testRequestID), resp)
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
			setExpectations: func(m *mock.Mock) {
				m.On("LoadActiveFlag", testUuid).Return(true, nil)
				m.On("Sign", &ubirch.SignedUPP{
					Version: ubirch.Signed,
					Uuid:    testUuid,
					Hint:    ubirch.Binary,
					Payload: testHash[:],
				}).Return(testUPP, nil)
				m.On("GetPublicKeyBytes", testUuid).Return(testPublicKey, nil)
				m.On("sendToAuthService", testUuid, testAuth, testUPP).Return(testBckndResp, nil)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, getSigningResponse(http.StatusOK, testHash[:], testUPP, testPublicKey, testBckndResp, testRequestID), resp)
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
			setExpectations: func(m *mock.Mock) {
				m.On("LoadActiveFlag", testUuid).Return(true, nil)
				m.On("Sign", &ubirch.SignedUPP{
					Version: ubirch.Signed,
					Uuid:    testUuid,
					Hint:    ubirch.Disable,
					Payload: testHash[:],
				}).Return(testUPP, nil)
				m.On("GetPublicKeyBytes", testUuid).Return(testPublicKey, nil)
				m.On("sendToAuthService", testUuid, testAuth, testUPP).Return(testBckndResp, nil)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, getSigningResponse(http.StatusOK, testHash[:], testUPP, testPublicKey, testBckndResp, testRequestID), resp)
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
			setExpectations: func(m *mock.Mock) {
				m.On("LoadActiveFlag", testUuid).Return(true, nil)
				m.On("Sign", &ubirch.SignedUPP{
					Version: ubirch.Signed,
					Uuid:    testUuid,
					Hint:    ubirch.Enable,
					Payload: testHash[:],
				}).Return(testUPP, nil)
				m.On("GetPublicKeyBytes", testUuid).Return(testPublicKey, nil)
				m.On("sendToAuthService", testUuid, testAuth, testUPP).Return(testBckndResp, nil)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, getSigningResponse(http.StatusOK, testHash[:], testUPP, testPublicKey, testBckndResp, testRequestID), resp)
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
			setExpectations: func(m *mock.Mock) {
				m.On("LoadActiveFlag", testUuid).Return(true, nil)
				m.On("Sign", &ubirch.SignedUPP{
					Version: ubirch.Signed,
					Uuid:    testUuid,
					Hint:    ubirch.Delete,
					Payload: testHash[:],
				}).Return(testUPP, nil)
				m.On("GetPublicKeyBytes", testUuid).Return(testPublicKey, nil)
				m.On("sendToAuthService", testUuid, testAuth, testUPP).Return(testBckndResp, nil)
			},
			tcChecks: func(t *testing.T, resp h.HTTPResponse, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, getSigningResponse(http.StatusOK, testHash[:], testUPP, testPublicKey, testBckndResp, testRequestID), resp)
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			m := &mock.Mock{}
			m.Test(t)
			c.setExpectations(m)

			s := Signer{
				Protocol:          &mockProto{mock: m},
				SendToAuthService: sendToAuthService(m),
			}

			resp := s.Sign(c.msg)

			c.tcChecks(t, resp, m)
		})
	}
}
