package http_server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testAuth = "password123"

func TestUpdateActive_Deactivate(t *testing.T) {
	payload := ActiveUpdatePayload{
		Uid:    uuid.New(),
		Active: false,
	}

	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(payloadBytes))
	r.Header.Set("Content-Type", JSONType)
	r.Header.Set(XAuthHeader, testAuth)

	UpdateActive(testAuth,
		func(uid uuid.UUID) error {
			assert.Equal(t, payload.Uid, uid)
			return nil
		},
		func(uid uuid.UUID) error {
			t.Error("reactivate function was called for deactivation")
			return nil
		})(w, r)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateActive_Reactivate(t *testing.T) {
	payload := ActiveUpdatePayload{
		Uid:    uuid.New(),
		Active: true,
	}

	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(payloadBytes))
	r.Header.Set("Content-Type", JSONType)
	r.Header.Set(XAuthHeader, testAuth)

	UpdateActive(testAuth,
		func(uid uuid.UUID) error {
			t.Error("deactivate function was called for reactivation")
			return nil
		},
		func(uid uuid.UUID) error {
			assert.Equal(t, payload.Uid, uid)
			return nil
		})(w, r)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateActive_Unauthorized(t *testing.T) {
	payload := ActiveUpdatePayload{
		Uid: uuid.New(),
	}

	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(payloadBytes))
	r.Header.Set("Content-Type", JSONType)
	r.Header.Set(XAuthHeader, "invalid")

	UpdateActive(testAuth,
		func(uid uuid.UUID) error {
			t.Error("deactivate function was called with invalid auth")
			return nil
		},
		func(uid uuid.UUID) error {
			t.Error("reactivate function was called with invalid auth")
			return nil
		})(w, r)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUpdateActive_InvalidContentType(t *testing.T) {
	payload := ActiveUpdatePayload{
		Uid: uuid.New(),
	}

	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(payloadBytes))
	r.Header.Set("Content-Type", BinType)
	r.Header.Set(XAuthHeader, testAuth)

	UpdateActive(testAuth,
		func(uid uuid.UUID) error {
			t.Error("deactivate function was called with invalid content type")
			return nil
		},
		func(uid uuid.UUID) error {
			t.Error("reactivate function was called with invalid content type")
			return nil
		})(w, r)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateActive_InvalidJSON(t *testing.T) {
	payload := ActiveUpdatePayload{
		Uid: uuid.New(),
	}

	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(payloadBytes[1:]))
	r.Header.Set("Content-Type", JSONType)
	r.Header.Set(XAuthHeader, testAuth)

	UpdateActive(testAuth,
		func(uid uuid.UUID) error {
			t.Error("deactivate function was called with invalid request content")
			return nil
		},
		func(uid uuid.UUID) error {
			t.Error("reactivate function was called with invalid request content")
			return nil
		})(w, r)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateActive_InvalidUUID(t *testing.T) {
	payload := ActiveUpdatePayload{}

	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(payloadBytes))
	r.Header.Set("Content-Type", JSONType)
	r.Header.Set(XAuthHeader, testAuth)

	UpdateActive(testAuth,
		func(uid uuid.UUID) error {
			t.Error("deactivate function was called with invalid request content")
			return nil
		},
		func(uid uuid.UUID) error {
			t.Error("reactivate function was called with invalid request content")
			return nil
		})(w, r)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateActive_Unknown(t *testing.T) {
	payload := ActiveUpdatePayload{
		Uid:    uuid.New(),
		Active: false,
	}

	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(payloadBytes))
	r.Header.Set("Content-Type", JSONType)
	r.Header.Set(XAuthHeader, testAuth)

	UpdateActive(testAuth,
		func(uid uuid.UUID) error {
			return ErrUnknown
		},
		func(uid uuid.UUID) error {
			t.Error("reactivate function was called for deactivation")
			return nil
		})(w, r)

	require.Equal(t, http.StatusNotFound, w.Code)
	require.Equal(t, ErrUnknown.Error()+"\n", w.Body.String())
}

func TestUpdateActive_Conflict(t *testing.T) {
	payload := ActiveUpdatePayload{
		Uid:    uuid.New(),
		Active: false,
	}

	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(payloadBytes))
	r.Header.Set("Content-Type", JSONType)
	r.Header.Set(XAuthHeader, testAuth)

	UpdateActive(testAuth,
		func(uid uuid.UUID) error {
			return ErrAlreadyDeactivated
		},
		func(uid uuid.UUID) error {
			t.Error("reactivate function was called for deactivation")
			return nil
		})(w, r)

	require.Equal(t, http.StatusConflict, w.Code)
	require.Equal(t, ErrAlreadyDeactivated.Error()+"\n", w.Body.String())
}

func TestUpdateActive_ServerError(t *testing.T) {
	payload := ActiveUpdatePayload{
		Uid:    uuid.New(),
		Active: false,
	}

	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(payloadBytes))
	r.Header.Set("Content-Type", JSONType)
	r.Header.Set(XAuthHeader, testAuth)

	UpdateActive(testAuth,
		func(uid uuid.UUID) error {
			return fmt.Errorf("some error")
		},
		func(uid uuid.UUID) error {
			t.Error("reactivate function was called for deactivation")
			return nil
		})(w, r)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}
