package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"testing"
	"time"
)

//For these tests to work the client needs to be started and reachable at the following address
const (
	defaultClientAddress = "http://localhost:8080"
	defaultUUID          = ""
	defaultAuthToken     = ""
)

//Struct for testing JSON marshaling
type TestDataStruct struct {
	Name    string
	Value   int
	Created time.Time
}

func createJSONRequest(address string, authToken string, uuidString string, jsonBytes []byte) (*http.Request, error) {
	url := address + "/" + uuidString
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBytes))
	req.Header.Set("X-Auth-Token", authToken)
	req.Header.Set("Content-Type", "application/json")
	return req, err
}

func createHashRequest(address string, authToken string, uuidString string, hashBytes []byte) (*http.Request, error) {
	url := address + "/" + uuidString + "/hash"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(hashBytes))
	req.Header.Set("X-Auth-Token", authToken)
	req.Header.Set("Content-Type", "application/octet-stream")
	return req, err
}

func TestHashRandom(t *testing.T) {
	const nrOfTests = 50
	const nrOfRetries = 5 // How often to resend a packet when backend does not reply with 200

	hashBytes := make([]byte, 32)
	retries := 0
	client := &http.Client{}

	rand.Read(hashBytes) //create very first hash

	for currTest := 0; currTest < nrOfTests; {
		//fmt.Println("Creating request")
		req, err := createHashRequest(defaultClientAddress, defaultAuthToken, defaultUUID, hashBytes)
		if err != nil {
			t.Fatal("Failed to create random hash request, aborting")
		}
		//fmt.Println("Doing request")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to do request: %v", err)
		}
		defer resp.Body.Close()
		//Check for error response
		if resp.StatusCode == 200 { //everything was OK
			rand.Read(hashBytes) //generate new Hash for next request
			currTest++           //increase test counter
			retries = 0          //reset retries counter
		} else { //unexpected response
			body, _ := ioutil.ReadAll(resp.Body)
			t.Logf("Unexpected response code (%v) received", resp.StatusCode)
			t.Logf("Response body was: %v", hex.EncodeToString(body))

			if retries < nrOfRetries {
				retries++
				t.Logf("Retrying request (%v/%v) for hash %v", retries, nrOfRetries, hex.EncodeToString(hashBytes))
			} else { //we retried to often, request/hash is considered failing permanently
				t.Errorf("Max. retries reached. Could not perform request with hash %v", hex.EncodeToString(hashBytes))
				//continue with next hash
				rand.Read(hashBytes) //generate new Hash for next request
				currTest++           //increase test counter
				retries = 0          //reset retries counter
			}

		}
	}
}
