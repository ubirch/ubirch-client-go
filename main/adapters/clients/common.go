package clients

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"

	h "github.com/ubirch/ubirch-client-go/main/adapters/http_server"
)

// Post submits a message to a backend service
// returns the response or encountered errors
func Post(serviceURL string, data []byte, header map[string]string) (h.HTTPResponse, error) {
	client := &http.Client{Timeout: h.BackendRequestTimeout}

	req, err := http.NewRequest(http.MethodPost, serviceURL, bytes.NewBuffer(data))
	if err != nil {
		return h.HTTPResponse{}, fmt.Errorf("can't make new post request: %v", err)
	}

	for k, v := range header {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return h.HTTPResponse{}, err
	}

	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	respBodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return h.HTTPResponse{}, err
	}

	return h.HTTPResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Content:    respBodyBytes,
	}, nil
}
