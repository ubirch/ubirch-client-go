package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
)

func returnErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	log.Println(message)
	w.WriteHeader(statusCode)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(message))
}

func handleRequest(srv *HTTPServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// only accept POST requests
		if r.Method != "POST" {
			returnErrorResponse(w, http.StatusNotFound, fmt.Sprintf("%s not implemented", r.Method))
			return
		}

		if strings.ToLower(r.Header.Get("Content-Type")) != "application/json" {
			returnErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("content type not supported"))
			return
		}

		// get UUID from URL path
		pathID := strings.TrimPrefix(r.URL.Path, srv.Endpoint)
		id, err := uuid.Parse(pathID)
		if err != nil {
			returnErrorResponse(w, http.StatusNotFound, http.StatusText(http.StatusNotFound))
			return
		}

		// check if UUID is known
		idAuth, exists := srv.Auth[id.String()]
		if !exists {
			returnErrorResponse(w, http.StatusNotFound, http.StatusText(http.StatusNotFound))
			return
		}

		// check authorization
		reqAuth := r.Header.Get("X-Auth-Token")
		if reqAuth != idAuth {
			returnErrorResponse(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
			return
		}

		// read request body
		reqBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			returnErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("error reading request body: %v", err))
			return
		}

		var reqDump interface{}
		var compactSortedJson bytes.Buffer

		err = json.Unmarshal(reqBody, &reqDump)
		if err != nil {
			returnErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("error parsing request body: %v", err))
			return
		}
		sortedJson, _ := json.Marshal(reqDump)           // json.Marshal sorts the keys
		_ = json.Compact(&compactSortedJson, sortedJson) // json.Compact removes insignificant space characters

		srv.ReceiveHandler <- append(id[:], compactSortedJson.Bytes()...)

		// wait for response from ubirch backend to be forwarded to sender
		// FIXME this will just wait for the next response, which is not necessarily the one corresponding to the request
		resp := <-srv.ResponseHandler
		w.WriteHeader(resp.Code)
		for k, v := range resp.Header {
			w.Header().Set(k, v[0])
		}
		w.Write(resp.Content)
	}
}

type HTTPServer struct {
	ReceiveHandler  chan []byte
	ResponseHandler chan HTTPResponse
	Endpoint        string
	Auth            map[string]string
}

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

type NewHandlers struct {
	Signer
}

func (h *NewHandlers) SignerHandler(w http.ResponseWriter, r *http.Request) {
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
	id, err := uuid.Parse(strings.TrimPrefix(r.URL.Path, srv.Endpoint))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	// check if UUID is known
	idAuth, exists := srv.Auth[id.String()]
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

	srv.ReceiveHandler <- append(id[:], compactSortedJson.Bytes()...)

	resp := h.Signer.Sign(HTTPMessage{})
}

func (h *NewHandlers) VerifyHandler(w http.ResponseWriter, r *http.Request) {

}

func (srv *HTTPServer) Listen(ctx context.Context, wg *sync.WaitGroup) {
	s := &http.Server{Addr: ":8080"}
	http.HandleFunc(srv.Endpoint+"/", handleRequest(srv))

	go func() {
		<-ctx.Done()
		log.Printf("shutting down http service (%s)", srv.Endpoint)
		s.Shutdown(ctx)
	}()

	go func() {
		defer wg.Done()
		err := s.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Printf("error starting http service: %v", err)
		}
	}()
}
