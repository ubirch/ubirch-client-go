package http_server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/ubirch/ubirch-client-go/main/config"
)

func initialize(m *mock.Mock) InitializeIdentity {
	return func(uid uuid.UUID, auth string) (csr []byte, err error) {
		args := m.MethodCalled("initialize", uid, auth)
		return args.Get(0).([]byte), args.Error(1)
	}
}

func getCSR(m *mock.Mock) GetCSR {
	return func(uid uuid.UUID) (csr []byte, err error) {
		args := m.MethodCalled("getCSR", uid)
		return args.Get(0).([]byte), args.Error(1)
	}
}

func checkAuth(m *mock.Mock) CheckAuth {
	return func(ctx context.Context, uid uuid.UUID, auth string) (ok, found bool, err error) {
		args := m.MethodCalled("checkAuth", ctx, uid, auth)
		return args.Bool(0), args.Bool(1), args.Error(2)
	}
}

func sign(m *mock.Mock) Sign {
	return func(msg HTTPRequest) (resp HTTPResponse) {
		args := m.MethodCalled("sign", msg.ID, msg.Auth, msg.Hash, msg.Operation, msg.Offline)
		return args.Get(0).(HTTPResponse)
	}
}

func verify(m *mock.Mock) Verify {

	return func(ctx context.Context, hash []byte) HTTPResponse {
		return HTTPResponse{}
	}
}

func verifyOffline(m *mock.Mock) VerifyOffline {

	return func(upp []byte, hash []byte) HTTPResponse {
		return HTTPResponse{}
	}
}

func deactivate(m *mock.Mock) UpdateActivateStatus {
	return func(uid uuid.UUID) error {
		args := m.MethodCalled("deactivate", uid)
		return args.Error(0)
	}
}

func reactivate(m *mock.Mock) UpdateActivateStatus {
	return func(uid uuid.UUID) error {
		args := m.MethodCalled("reactivate", uid)
		return args.Error(0)
	}
}

var (
	serverID        = "test server"
	readinessChecks []func() error
)

func TestInitHTTPServer(t *testing.T) {

	testCases := []struct {
		name            string
		request         *http.Request
		setExpectations func(m *mock.Mock)
		tcChecks        func(t *testing.T, w *httptest.ResponseRecorder, m *mock.Mock)
	}{
		{
			name:            "health check",
			request:         httptest.NewRequest(http.MethodGet, "/healthz", nil),
			setExpectations: func(m *mock.Mock) {},
			tcChecks: func(t *testing.T, w *httptest.ResponseRecorder, m *mock.Mock) {
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Equal(t, serverID, w.Header().Get("Server"))
				assert.Contains(t, w.Body.String(), http.StatusText(http.StatusOK))
			},
		},
		{
			name:            "readiness check",
			request:         httptest.NewRequest(http.MethodGet, "/readyz", nil),
			setExpectations: func(m *mock.Mock) {},
			tcChecks: func(t *testing.T, w *httptest.ResponseRecorder, m *mock.Mock) {
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Equal(t, serverID, w.Header().Get("Server"))
				assert.Contains(t, w.Body.String(), http.StatusText(http.StatusOK))
			},
		},
		{
			name:            "metrics",
			request:         httptest.NewRequest(http.MethodGet, "/metrics", nil),
			setExpectations: func(m *mock.Mock) {},
			tcChecks: func(t *testing.T, w *httptest.ResponseRecorder, m *mock.Mock) {
				assert.Equal(t, http.StatusOK, w.Code)
				// fixme
				//  assert.Contains(t, w.Body.String(), "http_requests_total")
				//  assert.Contains(t, w.Body.String(), "response_status")
				//  assert.Contains(t, w.Body.String(), "http_response_time_seconds")
				assert.Contains(t, w.Body.String(), "identity_creation_success")
			},
		},
		{
			name: "identity registration",
			request: func() *http.Request {
				payload := []byte("{\"uuid\": \"5133fbdd-978d-4f95-9af9-41abdef2f2b4\", \"password\": \"1234\"}")
				request := httptest.NewRequest(http.MethodPut, "/register", bytes.NewReader(payload))
				request.Header.Add(XAuthHeader, testAuth)
				request.Header.Add("Content-Type", JSONType)
				return request
			}(),
			setExpectations: func(m *mock.Mock) {
				m.On("initialize", uuid.MustParse("5133fbdd-978d-4f95-9af9-41abdef2f2b4"), "1234").Return([]byte("csr"), nil)
			},
			tcChecks: func(t *testing.T, w *httptest.ResponseRecorder, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Contains(t, w.Body.String(), "csr")
			},
		},
		{
			name: "CSR creation",
			request: func() *http.Request {
				request := httptest.NewRequest(http.MethodGet, "/5133fbdd-978d-4f95-9af9-41abdef2f2b4/csr", nil)
				request.Header.Add(XAuthHeader, testAuth)
				return request
			}(),
			setExpectations: func(m *mock.Mock) {
				m.On("getCSR", uuid.MustParse("5133fbdd-978d-4f95-9af9-41abdef2f2b4")).Return([]byte("csr"), nil)
			},
			tcChecks: func(t *testing.T, w *httptest.ResponseRecorder, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Contains(t, w.Body.String(), "csr")
			},
		},
		{
			name: "deactivation",
			request: func() *http.Request {
				payload := []byte("{\"id\": \"5133fbdd-978d-4f95-9af9-41abdef2f2b4\", \"active\": false}")
				request := httptest.NewRequest(http.MethodPut, "/device/updateActive", bytes.NewReader(payload))
				request.Header.Add(XAuthHeader, testAuth)
				request.Header.Add("Content-Type", JSONType)
				return request
			}(),
			setExpectations: func(m *mock.Mock) {
				m.On("deactivate", uuid.MustParse("5133fbdd-978d-4f95-9af9-41abdef2f2b4")).Return(nil)
			},
			tcChecks: func(t *testing.T, w *httptest.ResponseRecorder, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Contains(t, w.Body.String(), "key deactivation successful")
			},
		},
		{
			name: "reactivation",
			request: func() *http.Request {
				payload := []byte("{\"id\": \"5133fbdd-978d-4f95-9af9-41abdef2f2b4\", \"active\": true}")
				request := httptest.NewRequest(http.MethodPut, "/device/updateActive", bytes.NewReader(payload))
				request.Header.Add(XAuthHeader, testAuth)
				request.Header.Add("Content-Type", JSONType)
				return request
			}(),
			setExpectations: func(m *mock.Mock) {
				m.On("reactivate", uuid.MustParse("5133fbdd-978d-4f95-9af9-41abdef2f2b4")).Return(nil)
			},
			tcChecks: func(t *testing.T, w *httptest.ResponseRecorder, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Contains(t, w.Body.String(), "key reactivation successful")
			},
		},
		{
			name: "chain",
			request: func() *http.Request {
				payload := []byte("{\"c\": \"d\", \"a\": \"b\", \"e\": \"f\"}")
				request := httptest.NewRequest(http.MethodPost, "/5133fbdd-978d-4f95-9af9-41abdef2f2b4", bytes.NewReader(payload))
				request.Header.Add(XAuthHeader, testAuth)
				request.Header.Add("Content-Type", JSONType)
				return request
			}(),
			setExpectations: func(m *mock.Mock) {
				// checkAuth(ctx context.Context, uid uuid.UUID, auth string) (ok, found bool, err error)
				m.On("checkAuth", mock.AnythingOfType("*context.timerCtx"), uuid.MustParse("5133fbdd-978d-4f95-9af9-41abdef2f2b4"), testAuth).Return(true, true, nil)
				m.On("sign",
					uuid.MustParse("5133fbdd-978d-4f95-9af9-41abdef2f2b4"),
					testAuth,
					Sha256Sum{0x80, 0xc9, 0x83, 0xc2, 0xfa, 0x61, 0x75, 0x1b, 0x2f, 0x78, 0x42, 0xa3, 0xa3, 0x39, 0x34, 0xfc, 0xbe, 0xd1, 0xc4, 0x3a, 0xa2, 0x5c, 0xa3, 0xb6, 0x39, 0x5c, 0x12, 0xf5, 0x53, 0xe2, 0xf0, 0x5e},
					ChainHash,
					false,
				).Return(HTTPResponse{
					StatusCode: http.StatusOK,
					//Header:     http.Header{"test": []string{"1", "2", "3"}},
					Header:  http.Header{"test": []string{"header"}},
					Content: []byte("chained"),
				})
			},
			tcChecks: func(t *testing.T, w *httptest.ResponseRecorder, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, http.StatusOK, w.Code)
				//assert.Equal(t, []string{"1", "2", "3"}, w.Header().Get("test"))
				assert.Equal(t, "header", w.Header().Get("test"))
				assert.Contains(t, w.Body.String(), "chained")
			},
		},
		{
			name: "chain hash",
			request: func() *http.Request {
				payload := []byte("gMmDwvphdRsveEKjozk0/L7RxDqiXKO2OVwS9VPi8F4=")
				request := httptest.NewRequest(http.MethodPost, "/5133fbdd-978d-4f95-9af9-41abdef2f2b4/hash", bytes.NewReader(payload))
				request.Header.Add(XAuthHeader, testAuth)
				request.Header.Add("Content-Type", "text/plain")
				return request
			}(),
			setExpectations: func(m *mock.Mock) {
				m.On("checkAuth", mock.AnythingOfType("*context.timerCtx"), uuid.MustParse("5133fbdd-978d-4f95-9af9-41abdef2f2b4"), testAuth).Return(true, true, nil)
				m.On("sign",
					uuid.MustParse("5133fbdd-978d-4f95-9af9-41abdef2f2b4"),
					testAuth,
					Sha256Sum{0x80, 0xc9, 0x83, 0xc2, 0xfa, 0x61, 0x75, 0x1b, 0x2f, 0x78, 0x42, 0xa3, 0xa3, 0x39, 0x34, 0xfc, 0xbe, 0xd1, 0xc4, 0x3a, 0xa2, 0x5c, 0xa3, 0xb6, 0x39, 0x5c, 0x12, 0xf5, 0x53, 0xe2, 0xf0, 0x5e},
					ChainHash,
					false,
				).Return(HTTPResponse{
					StatusCode: http.StatusOK,
					Header:     http.Header{"test": []string{"header"}},
					Content:    []byte("chained hash"),
				})
			},
			tcChecks: func(t *testing.T, w *httptest.ResponseRecorder, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Equal(t, "header", w.Header().Get("test"))
				assert.Contains(t, w.Body.String(), "chained hash")
			},
		},
		{
			name: "chain offline",
			request: func() *http.Request {
				payload := []byte("{\"c\": \"d\", \"a\": \"b\", \"e\": \"f\"}")
				request := httptest.NewRequest(http.MethodPost, "/5133fbdd-978d-4f95-9af9-41abdef2f2b4/offline", bytes.NewReader(payload))
				request.Header.Add(XAuthHeader, testAuth)
				request.Header.Add("Content-Type", JSONType)
				return request
			}(),
			setExpectations: func(m *mock.Mock) {
				m.On("checkAuth", mock.AnythingOfType("*context.timerCtx"), uuid.MustParse("5133fbdd-978d-4f95-9af9-41abdef2f2b4"), testAuth).Return(true, true, nil)
				m.On("sign",
					uuid.MustParse("5133fbdd-978d-4f95-9af9-41abdef2f2b4"),
					testAuth,
					Sha256Sum{0x80, 0xc9, 0x83, 0xc2, 0xfa, 0x61, 0x75, 0x1b, 0x2f, 0x78, 0x42, 0xa3, 0xa3, 0x39, 0x34, 0xfc, 0xbe, 0xd1, 0xc4, 0x3a, 0xa2, 0x5c, 0xa3, 0xb6, 0x39, 0x5c, 0x12, 0xf5, 0x53, 0xe2, 0xf0, 0x5e},
					ChainHash,
					true,
				).Return(HTTPResponse{
					StatusCode: http.StatusOK,
					Header:     http.Header{"test": []string{"header"}},
					Content:    []byte("chained offline"),
				})
			},
			tcChecks: func(t *testing.T, w *httptest.ResponseRecorder, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Equal(t, "header", w.Header().Get("test"))
				assert.Contains(t, w.Body.String(), "chained offline")
			},
		},
		{
			name: "chain offline hash",
			request: func() *http.Request {
				payload := []byte("gMmDwvphdRsveEKjozk0/L7RxDqiXKO2OVwS9VPi8F4=")
				request := httptest.NewRequest(http.MethodPost, "/5133fbdd-978d-4f95-9af9-41abdef2f2b4/offline/hash", bytes.NewReader(payload))
				request.Header.Add(XAuthHeader, testAuth)
				request.Header.Add("Content-Type", "text/plain")
				return request
			}(),
			setExpectations: func(m *mock.Mock) {
				m.On("checkAuth", mock.AnythingOfType("*context.timerCtx"), uuid.MustParse("5133fbdd-978d-4f95-9af9-41abdef2f2b4"), testAuth).Return(true, true, nil)
				m.On("sign",
					uuid.MustParse("5133fbdd-978d-4f95-9af9-41abdef2f2b4"),
					testAuth,
					Sha256Sum{0x80, 0xc9, 0x83, 0xc2, 0xfa, 0x61, 0x75, 0x1b, 0x2f, 0x78, 0x42, 0xa3, 0xa3, 0x39, 0x34, 0xfc, 0xbe, 0xd1, 0xc4, 0x3a, 0xa2, 0x5c, 0xa3, 0xb6, 0x39, 0x5c, 0x12, 0xf5, 0x53, 0xe2, 0xf0, 0x5e},
					ChainHash,
					true,
				).Return(HTTPResponse{
					StatusCode: http.StatusOK,
					Header:     http.Header{"test": []string{"header"}},
					Content:    []byte("chained offline hash"),
				})
			},
			tcChecks: func(t *testing.T, w *httptest.ResponseRecorder, m *mock.Mock) {
				m.AssertExpectations(t)
				assert.Equal(t, http.StatusOK, w.Code)
				assert.Equal(t, "header", w.Header().Get("test"))
				assert.Contains(t, w.Body.String(), "chained offline hash")
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			m := &mock.Mock{}
			m.Test(t)
			c.setExpectations(m)

			conf := &config.Config{
				RegisterAuth:     testAuth,
				GatewayTimeoutMs: int64(time.Second),
			}

			httpServer := InitHTTPServer(conf,
				initialize(m), getCSR(m),
				checkAuth(m), sign(m),
				verify(m), verifyOffline(m),
				deactivate(m), reactivate(m),
				serverID, readinessChecks)

			w := httptest.NewRecorder()

			httpServer.Router.ServeHTTP(w, c.request)

			c.tcChecks(t, w, m)
		})
	}
}

const (
	testInputStr string = "{\n  \"id\": \"ba70ad8b-a564-4e58-9a3b-224ac0f0153f\",\n  \"ts\": 1613733623,\n  \"big\": 5102163654257655,\n  \"tpl\": [\n    801874468,\n    \"<f,c\",\n    66,\n    \"#_Ÿ1cb\",\n    19875,\n    \"#d\",\n    10,\n    \"}d$\\\\n'™!&#8482{ï\\\"e%7ü\"\n  ],\n  \"lst\": [\n    \"%20\",\n    \"5\",\n    \"6\",\n    \"_\",\n    \"_\",\n    \"c\",\n    \"Ï\",\n    \"D\"\n  ],\n  \"map\": {\n    \"Ë\": 11,\n    \"F\": 44464,\n    \"`\": 114,\n    \"\": 2033005546\n  },\n  \"str\": \" |8_;5Ï®d;F),$:bfä\\\\nÿd./A\\\"9(£C8< |Ï(Ä[äü2\\\\,fU+2122e07]{9Eë`_Df);C])¬ÿ:7 |9}DË+f?U+2122ïa(®%E:8£27&\\\\&ÜU+2122Äc+!0f!ü™4Äb4'`.ÄÄ0$ü;~Fc'8'8e0ÄAfEC<}\"\n}"
	expOutputStr string = "{\"big\":5102163654257655,\"id\":\"ba70ad8b-a564-4e58-9a3b-224ac0f0153f\",\"lst\":[\"%20\",\"5\",\"6\",\"_\",\"_\",\"c\",\"Ï\",\"D\"],\"map\":{\"\":2033005546,\"F\":44464,\"`\":114,\"Ë\":11},\"str\":\" |8_;5Ï®d;F),$:bfä\\\\nÿd./A\\\"9(£C8< |Ï(Ä[äü2\\\\,fU+2122e07]{9Eë`_Df);C])¬ÿ:7 |9}DË+f?U+2122ïa(®%E:8£27&\\\\&ÜU+2122Äc+!0f!ü™4Äb4'`.ÄÄ0$ü;~Fc'8'8e0ÄAfEC<}\",\"tpl\":[801874468,\"<f,c\",66,\"#_Ÿ1cb\",19875,\"#d\",10,\"}d$\\\\n'™!&#8482{ï\\\"e%7ü\"],\"ts\":1613733623}"
	expHash_64   string = "eOp3knHnkZ3Hu7q33OGl4EwC5hXrPK78STk76cMfI4Q="
)

func TestSortedCompactJson(t *testing.T) {
	var tests = []struct {
		testInput      []byte
		expectedOutput []byte
		expectedHash   string
	}{
		{
			testInput:      []byte(testInputStr),
			expectedOutput: []byte(expOutputStr),
			expectedHash:   expHash_64,
		},
	}

	for _, test := range tests {
		out, err := GetSortedCompactJSON(test.testInput)
		if err != nil {
			t.Errorf("getSortedCompactJSON returned error: %v", err)
		}

		if !bytes.Equal(out, test.expectedOutput) {
			t.Errorf("getSortedCompactJSON did not return expected output:\n"+
				"- expected: %s\n"+
				"-      got: %s", test.expectedOutput, out)
		}

		hash := sha256.Sum256(out)
		expHash, err := base64.StdEncoding.DecodeString(test.expectedHash)
		if err != nil {
			t.Errorf("could not decode expected hash from base64 string: %v", err)
		}

		if !bytes.Equal(hash[:], expHash) {
			t.Errorf("hash not as expected:\n"+
				"- expected: %s\n"+
				"-      got: %s", test.expectedHash, base64.StdEncoding.EncodeToString(hash[:]))
		}
	}
}
