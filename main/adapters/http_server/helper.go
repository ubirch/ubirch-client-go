package http_server

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

// helper function to get "Content-Type" from request header
func ContentType(header http.Header) string {
	return strings.ToLower(header.Get("Content-Type"))
}

// helper function to get "Content-Transfer-Encoding" from request header
func ContentEncoding(header http.Header) string {
	return strings.ToLower(header.Get("Content-Transfer-Encoding"))
}

// helper function to get "X-Auth-Token" from request header
func AuthToken(header http.Header) string {
	return header.Get(XAuthHeader)
}

func ReadBody(r *http.Request) ([]byte, error) {
	rBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read request body: %v", err)
	}
	return rBody, nil
}

func HttpFailed(StatusCode int) bool {
	return !HttpSuccess(StatusCode)
}

func HttpSuccess(StatusCode int) bool {
	return StatusCode >= 200 && StatusCode < 300
}
