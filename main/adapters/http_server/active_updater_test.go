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

var testUUID = uuid.MustParse("392110c4-5c4e-482c-80ef-e288ede02462")

func TestUpdateActive(t *testing.T) {

	testCases := []struct {
		name        string
		payload     ActiveUpdatePayload
		deactivate  UpdateActivateStatus
		reactivate  UpdateActivateStatus
		auth        string
		contentType string
		tcChecks    func(t *testing.T, recorder *httptest.ResponseRecorder)
	}{
		{
			name: "Deactivate",
			payload: ActiveUpdatePayload{
				Uid:    testUUID,
				Active: false,
			},
			deactivate: func(uid uuid.UUID) error {
				assert.Equal(t, testUUID, uid)
				return nil
			},
			reactivate: func(uid uuid.UUID) error {
				t.Error("reactivate function was called for deactivation")
				return nil
			},
			auth:        testAuth,
			contentType: JSONType,
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusOK, recorder.Code)
				assert.Contains(t, recorder.Body.String(), deactivation)
			},
		},
		{
			name: "Reactivate",
			payload: ActiveUpdatePayload{
				Uid:    testUUID,
				Active: true,
			},
			deactivate: func(uid uuid.UUID) error {
				t.Error("deactivate function was called for reactivation")
				return nil
			},
			reactivate: func(uid uuid.UUID) error {
				assert.Equal(t, testUUID, uid)
				return nil
			},
			auth:        testAuth,
			contentType: JSONType,
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusOK, recorder.Code)
				assert.Contains(t, recorder.Body.String(), reactivation)
			},
		},
		{
			name: "Unauthorized",
			payload: ActiveUpdatePayload{
				Uid: testUUID,
			},
			deactivate: func(uid uuid.UUID) error {
				t.Error("deactivate function was called with invalid auth")
				return nil
			},
			reactivate: func(uid uuid.UUID) error {
				t.Error("reactivate function was called with invalid auth")
				return nil
			},
			auth:        "invalid",
			contentType: JSONType,
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusUnauthorized, recorder.Code)
				assert.Contains(t, recorder.Body.String(), http.StatusText(http.StatusUnauthorized))
			},
		},
		{
			name: "InvalidContentType",
			payload: ActiveUpdatePayload{
				Uid: testUUID,
			},
			deactivate: func(uid uuid.UUID) error {
				t.Error("deactivate function was called with invalid content type")
				return nil
			},
			reactivate: func(uid uuid.UUID) error {
				t.Error("reactivate function was called with invalid content type")
				return nil
			},
			auth:        testAuth,
			contentType: BinType,
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusBadRequest, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "invalid content-type")
			},
		},
		{
			name:    "InvalidUUID",
			payload: ActiveUpdatePayload{},
			deactivate: func(uid uuid.UUID) error {
				t.Error("deactivate function was called with invalid UUID")
				return nil
			},
			reactivate: func(uid uuid.UUID) error {
				t.Error("reactivate function was called with invalid UUID")
				return nil
			},
			auth:        testAuth,
			contentType: JSONType,
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusBadRequest, recorder.Code)
				assert.Contains(t, recorder.Body.String(), "empty uuid")
			},
		},
		{
			name: "Unknown",
			payload: ActiveUpdatePayload{
				Uid: testUUID,
			},
			deactivate: func(uid uuid.UUID) error {
				return ErrUnknown
			},
			reactivate: func(uid uuid.UUID) error {
				t.Error("reactivate function was called for deactivation")
				return nil
			},
			auth:        testAuth,
			contentType: JSONType,
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusNotFound, recorder.Code)
				assert.Contains(t, recorder.Body.String(), ErrUnknown.Error())
			},
		},
		{
			name: "Conflict",
			payload: ActiveUpdatePayload{
				Uid: testUUID,
			},
			deactivate: func(uid uuid.UUID) error {
				return ErrAlreadyDeactivated
			},
			reactivate: func(uid uuid.UUID) error {
				t.Error("reactivate function was called for deactivation")
				return nil
			},
			auth:        testAuth,
			contentType: JSONType,
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusConflict, recorder.Code)
				assert.Contains(t, recorder.Body.String(), ErrAlreadyDeactivated.Error())
			},
		},
		{
			name: "ServerError",
			payload: ActiveUpdatePayload{
				Uid: testUUID,
			},
			deactivate: func(uid uuid.UUID) error {
				return fmt.Errorf("some error")
			},
			reactivate: func(uid uuid.UUID) error {
				t.Error("reactivate function was called for deactivation")
				return nil
			},
			auth:        testAuth,
			contentType: JSONType,
			tcChecks: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusInternalServerError, recorder.Code)
				assert.Contains(t, recorder.Body.String(), http.StatusText(http.StatusInternalServerError))
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			payloadBytes, err := json.Marshal(c.payload)
			require.NoError(t, err)

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(payloadBytes))
			r.Header.Set("Content-Type", c.contentType)
			r.Header.Set(XAuthHeader, c.auth)

			UpdateActive(testAuth,
				c.deactivate,
				c.reactivate,
			)(w, r)
			c.tcChecks(t, w)
		})
	}
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
