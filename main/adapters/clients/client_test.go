package clients

import (
	"encoding/base64"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_RequestPublicKeys(t *testing.T) {
	testCases := []struct {
		name        string
		handlerfunc http.HandlerFunc
		tcChecks    func(t *testing.T, client Client)
	}{
		{
			name: "happy path",
			handlerfunc: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				// Send response to be tested
				ubirchKeys := NewSignedKeyregistration()
				rawKeys, err := json.Marshal(ubirchKeys)
				require.NoError(t, err)
				rw.Write(rawKeys)
			}),
			tcChecks: func(t *testing.T, client Client) {
				respKeys, err := client.RequestPublicKeys(uuid.New())
				require.NoError(t, err)
				require.Equal(t, NewSignedKeyregistration(), respKeys)
			},
		},
		{
			name: "no error if status not found",
			handlerfunc: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				// Send response to be tested
				rw.WriteHeader(http.StatusNotFound)
			}),
			tcChecks: func(t *testing.T, client Client) {
				respKeys, err := client.RequestPublicKeys(uuid.New())
				require.NoError(t, err)
				require.Equal(t, []ubirch.SignedKeyRegistration{}, respKeys)
			},
		},
		{
			name: "bad request",
			handlerfunc: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				// Send response to be tested
				rw.WriteHeader(http.StatusBadRequest)
			}),
			tcChecks: func(t *testing.T, client Client) {
				respKeys, err := client.RequestPublicKeys(uuid.New())
				require.Error(t, err)
				require.Nil(t, respKeys)
			},
		},
		{
			name: "status ok, but wrong response",
			handlerfunc: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.Write([]byte(`Not the signed Keys`))
			}),
			tcChecks: func(t *testing.T, client Client) {
				respKeys, err := client.RequestPublicKeys(uuid.New())
				require.Error(t, err)
				require.Nil(t, respKeys)
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			server := httptest.NewServer(c.handlerfunc)
			defer server.Close()
			client := Client{
				Client:             server.Client(),
				AuthServiceURL:     server.URL,
				VerifyServiceURL:   server.URL,
				KeyServiceURL:      server.URL,
				IdentityServiceURL: server.URL,
			}

			c.tcChecks(t, client)
		})
	}
}

func TestClient_IsKeyRegistered(t *testing.T) {
	testCases := []struct {
		name        string
		handlerfunc http.HandlerFunc
		tcChecks    func(t *testing.T, client Client)
	}{
		{
			name: "happy path",
			handlerfunc: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				// Send response to be tested
				ubirchKeys := NewSignedKeyregistration()
				rawKeys, err := json.Marshal(ubirchKeys)
				require.NoError(t, err)
				rw.Write(rawKeys)
			}),
			tcChecks: func(t *testing.T, client Client) {
				keyRegistered, err := client.IsKeyRegistered(uuid.New(), []byte(`test`))
				require.NoError(t, err)
				require.True(t, keyRegistered)
			},
		},
		{
			name: "No registered public key matches",
			handlerfunc: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				// Send response to be tested
				ubirchKeys := NewSignedKeyregistration()
				rawKeys, err := json.Marshal(ubirchKeys)
				require.NoError(t, err)
				rw.Write(rawKeys)
			}),
			tcChecks: func(t *testing.T, client Client) {
				keyRegistered, err := client.IsKeyRegistered(uuid.New(), []byte(`Not the public key`))
				require.NoError(t, err)
				require.False(t, keyRegistered)
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			server := httptest.NewServer(c.handlerfunc)
			defer server.Close()
			client := Client{
				Client:             server.Client(),
				AuthServiceURL:     server.URL,
				VerifyServiceURL:   server.URL,
				KeyServiceURL:      server.URL,
				IdentityServiceURL: server.URL,
			}

			c.tcChecks(t, client)
		})
	}
}

func TestClient_SubmitKeyRegistration(t *testing.T) {
	testCases := []struct {
		name        string
		handlerfunc http.HandlerFunc
		tcChecks    func(t *testing.T, client Client)
	}{
		{
			name: "happy path",
			handlerfunc: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				// Send response to be tested
				rw.Write([]byte(`OK`))
			}),
			tcChecks: func(t *testing.T, client Client) {
				err := client.SubmitKeyRegistration(uuid.New(), []byte(`test`), "auth")
				require.NoError(t, err)
			},
		},
		{
			name: "bad request",
			handlerfunc: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				// Send response to be tested
				rw.WriteHeader(http.StatusBadRequest)
			}),
			tcChecks: func(t *testing.T, client Client) {
				err := client.SubmitKeyRegistration(uuid.New(), []byte(`test`), "auth")
				require.Error(t, err)
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			server := httptest.NewServer(c.handlerfunc)
			defer server.Close()
			client := Client{
				Client:             server.Client(),
				AuthServiceURL:     server.URL,
				VerifyServiceURL:   server.URL,
				KeyServiceURL:      server.URL,
				IdentityServiceURL: server.URL,
			}

			c.tcChecks(t, client)
		})
	}
}

func TestClient_SubmitCSR(t *testing.T) {

	testCases := []struct {
		name        string
		handlerfunc http.HandlerFunc
		tcChecks    func(t *testing.T, client Client)
	}{
		{
			name: "happy path",
			handlerfunc: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				// Send response to be tested
				rw.Write([]byte(`OK`))
			}),
			tcChecks: func(t *testing.T, client Client) {
				err := client.SubmitCSR(uuid.New(), []byte(`test`))
				require.NoError(t, err)
			},
		},
		{
			name: "bad request",
			handlerfunc: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				// Send response to be tested
				rw.WriteHeader(http.StatusBadRequest)
			}),
			tcChecks: func(t *testing.T, client Client) {
				err := client.SubmitCSR(uuid.New(), []byte(`test`))
				require.Error(t, err)
			},
		},
	}
	for _, c := range testCases {
		t.Run(c.name, func(t *testing.T) {
			server := httptest.NewServer(c.handlerfunc)
			defer server.Close()
			client := Client{
				Client:             server.Client(),
				AuthServiceURL:     server.URL,
				VerifyServiceURL:   server.URL,
				KeyServiceURL:      server.URL,
				IdentityServiceURL: server.URL,
			}

			c.tcChecks(t, client)
		})
	}
}

func NewSignedKeyregistration() []ubirch.SignedKeyRegistration {
	return []ubirch.SignedKeyRegistration{
		{
			PubKeyInfo: ubirch.KeyRegistration{
				Algorithm:      "test",
				Created:        "test",
				HwDeviceId:     "test",
				PubKey:         base64.StdEncoding.EncodeToString([]byte(`test`)),
				PubKeyId:       "test",
				ValidNotAfter:  "test",
				ValidNotBefore: "test",
			},
			Signature: "test",
		},
		{
			PubKeyInfo: ubirch.KeyRegistration{
				Algorithm:      "test2",
				Created:        "test3",
				HwDeviceId:     "test4",
				PubKey:         "test5",
				PubKeyId:       "test6",
				ValidNotAfter:  "test7",
				ValidNotBefore: "test8",
			},
			Signature: "test7",
		},
	}
}
