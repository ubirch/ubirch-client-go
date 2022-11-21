package clients

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	h "github.com/ubirch/ubirch-client-go/main/adapters/http_server"
)

type UbirchServiceClient struct {
	IdentityServiceClient
	AuthenticationServiceClient
	VerificationServiceClient
}

func sendRequest(method string, serviceURL string, data []byte, header map[string]string, timeout time.Duration) (h.HTTPResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, serviceURL, bytes.NewBuffer(data))
	if err != nil {
		return h.HTTPResponse{}, fmt.Errorf("can't make new post request: %v", err)
	}

	for k, v := range header {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return h.HTTPResponse{}, err
	}

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return h.HTTPResponse{}, err
	}

	return h.HTTPResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Content:    respBodyBytes,
	}, nil
}
