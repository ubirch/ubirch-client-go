package handlers

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	h "github.com/ubirch/ubirch-client-go/main/adapters/httphelper"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIdentityCreator_Put(t *testing.T) {

	testCases := []struct {
		name          string
		auth          string
		contentType   string
		payload       IdentityPayload
		storeIdentity StoreIdentity
		checkIdentity CheckIdentityExists
		tcChecks      func(t *testing.T, recorder *httptest.ResponseRecorder)
	}{
		{
			name:        "happy path",
			auth:        "auth",
			contentType: h.JSONType,
			payload: IdentityPayload{
				Uid: "00a1439a-3b1b-4111-8ce9-31e481c9636d",
				Pwd: "secret",
			},
			storeIdentity: func(uid uuid.UUID, auth string) (csr []byte, err error) {
				return []byte("something"), nil
			},
			checkIdentity: func(uid uuid.UUID) (bool, error) {
				return false, nil
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusOK, recorder.Result().StatusCode)
				csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("something")})
				require.Equal(t, recorder.Body.String(), string(csr))
			},
		},
		{
			name:        "not authorized",
			auth:        "wrong auth",
			contentType: h.JSONType,
			payload: IdentityPayload{
				Uid: "00a1439a-3b1b-4111-8ce9-31e481c9636d",
				Pwd: "secret",
			},
			storeIdentity: func(uid uuid.UUID, auth string) (csr []byte, err error) {
				return nil, nil
			},
			checkIdentity: func(uid uuid.UUID) (bool, error) {
				return false, nil
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusUnauthorized, recorder.Result().StatusCode)
			},
		},
		{
			name:        "wrong content type",
			auth:        "auth",
			contentType: "",
			payload: IdentityPayload{
				Uid: "00a1439a-3b1b-4111-8ce9-31e481c9636d",
				Pwd: "secret",
			},
			storeIdentity: func(uid uuid.UUID, auth string) (csr []byte, err error) {
				return nil, nil
			},
			checkIdentity: func(uid uuid.UUID) (bool, error) {
				return false, nil
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusBadRequest, recorder.Result().StatusCode)
			},
		},
		{
			name:        "empty body",
			auth:        "auth",
			contentType: h.JSONType,
			payload: IdentityPayload{},
			storeIdentity: func(uid uuid.UUID, auth string) (csr []byte, err error) {
				return nil, nil
			},
			checkIdentity: func(uid uuid.UUID) (bool, error) {
				return false, nil
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusBadRequest, recorder.Result().StatusCode)
			},
		},
		{
			name:        "internal error check identity",
			auth:        "auth",
			contentType: h.JSONType,
			payload: IdentityPayload{
				Uid: "00a1439a-3b1b-4111-8ce9-31e481c9636d",
				Pwd: "secret",
			},
			storeIdentity: func(uid uuid.UUID, auth string) (csr []byte, err error) {
				return nil, nil
			},
			checkIdentity: func(uid uuid.UUID) (bool, error) {
				return false, fmt.Errorf("internal error")
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusInternalServerError, recorder.Result().StatusCode)
			},
		},
		{
			name:        "id exists",
			auth:        "auth",
			contentType: h.JSONType,
			payload: IdentityPayload{
				Uid: "00a1439a-3b1b-4111-8ce9-31e481c9636d",
				Pwd: "secret",
			},
			storeIdentity: func(uid uuid.UUID, auth string) (csr []byte, err error) {
				return nil, nil
			},
			checkIdentity: func(uid uuid.UUID) (bool, error) {
				return true, nil
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusConflict, recorder.Result().StatusCode)
			},
		},
		{
			name:        "store id error",
			auth:        "auth",
			contentType: h.JSONType,
			payload: IdentityPayload{
				Uid: "00a1439a-3b1b-4111-8ce9-31e481c9636d",
				Pwd: "secret",
			},
			storeIdentity: func(uid uuid.UUID, auth string) (csr []byte, err error) {
				return nil, fmt.Errorf("internal error")
			},
			checkIdentity: func(uid uuid.UUID) (bool, error) {
				return false, nil
			},
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusInternalServerError, recorder.Result().StatusCode)
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			router := h.NewRouter()
			identityCreator := NewIdentityCreator("auth")
			router.Put(fmt.Sprintf("/%s", h.RegisterEndpoint), identityCreator.Put(c.storeIdentity, c.checkIdentity))

			jsonPayload, err := json.Marshal(c.payload)
			require.NoError(t, err)

			req, err := http.NewRequest(http.MethodPut, "/register", bytes.NewReader(jsonPayload))
			require.NoError(t, err)

			req.Header.Set(h.XAuthHeader, c.auth)
			req.Header.Set(h.HeaderContentType, c.contentType)
			router.ServeHTTP(recorder, req)
			c.tcChecks(t, recorder)
		})
	}
}
