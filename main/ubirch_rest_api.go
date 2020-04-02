package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/go-chi/chi"
	"github.com/google/uuid"
)

type HTTPMessage struct {
	ID        uuid.UUID
	Msg       []byte
	AuthToken string
}

// GetUUID returns the device UUID that sent the HTTP request.
func (msg HTTPMessage) GetUUID() uuid.UUID {
	return msg.ID
}

// GetMessage returns the sorted compact rendering of the json formatted request body
func (msg HTTPMessage) GetMessage() []byte {
	return msg.Msg
}

// GetGetAuthToken returns the auth token from the request header
func (msg HTTPMessage) GetAuthToken() string {
	return msg.AuthToken
}

type HTTPResponse struct {
	Code    int
	Header  map[string][]string
	Content []byte
}

type HTTPSignHandlers struct {
	Signer  Signer
	AuthMap map[string]string
}

func (h *HTTPSignHandlers) SignerHandler(w http.ResponseWriter, r *http.Request) {
	// only accept POST requests
	if r.Method != "POST" {
		http.Error(w, fmt.Sprintf("%s not implemented", r.Method), http.StatusNotImplemented)
		return
	}

	// make sure request body is of type json
	if strings.ToLower(r.Header.Get("Content-Type")) != "application/json" {
		http.Error(w, "Wrong request body type", http.StatusBadRequest)
		return
	}

	// get UUID from URL path
	id, err := uuid.Parse(chi.URLParam(r, "uuid"))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	// check if UUID is known
	idAuth, exists := h.AuthMap[id.String()]
	if !exists {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	// check authorization
	reqAuth := r.Header.Get("X-Auth-Token")
	if reqAuth != idAuth {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// read request body
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error reading request body: %v", err), http.StatusBadRequest)
		return
	}

	// generate a sorted compact rendering of the json formatted request body
	var reqDump interface{}
	var compactSortedJson bytes.Buffer

	err = json.Unmarshal(reqBody, &reqDump)
	if err != nil {
		http.Error(w, fmt.Sprintf("error parsing request body: %v", err), http.StatusBadRequest)
		return
	}

	// json.Marshal sorts the keys
	sortedJson, _ := json.Marshal(reqDump)
	_ = json.Compact(&compactSortedJson, sortedJson)

	resp := h.Signer.Sign(HTTPMessage{ID: id, Msg: compactSortedJson.Bytes(), AuthToken: idAuth})

	w.WriteHeader(resp.Code)
	for k, v := range resp.Header {
		w.Header().Set(k, v[0])
	}
	w.Write(resp.Content)
}
