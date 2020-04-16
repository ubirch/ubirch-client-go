package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//For these tests to work the client needs to be started and reachable at the following address
const (
	defaultClientAddress = "http://localhost:8080"
	//defaultUUID          = ""
	//defaultAuthToken     = ""
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

// TestHashRandom tests if hash signing request with random hashes always succeed. It tries a
// defined number of times before flagging a certain hash as causing an error to allow for timeouts/packet
// loss when talking to the backend.
func TestHashRandom(t *testing.T) {
	const nrOfTests = 5 //how many random hashes to send
	const nrOfTries = 5 // How often to send a packet (if backend does not reply with 200)

	hashBytes := make([]byte, 32)
	tries := 0
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
			t.Fatalf("Failed to do request: %v. \n Is the client started and reachable?", err)
		}
		defer resp.Body.Close()
		//Check for error response
		if resp.StatusCode == 200 { //everything was OK
			rand.Read(hashBytes) //generate new Hash for next request
			currTest++           //increase test counter
			tries = 0            //reset tries counter
		} else { //unexpected response
			body, _ := ioutil.ReadAll(resp.Body)
			t.Logf("Unexpected response code (%v) received", resp.StatusCode)
			t.Logf("Response body was: %v", hex.EncodeToString(body))

			if tries < nrOfTries {
				tries++
				t.Logf("Try (%v/%v) for hash %v failed", tries, nrOfTries, hex.EncodeToString(hashBytes))
			} else { //we retried to often, request/hash is considered failing permanently
				t.Errorf("Max. tries reached. Could not perform request with hash %v", hex.EncodeToString(hashBytes))
				//continue with next hash
				rand.Read(hashBytes) //generate new Hash for next request
				currTest++           //increase test counter
				tries = 0            //reset tries counter
			}

		}
	}
}

//TestHashSpecificFail tests cases with a specific hash as an input which must fail
func TestHashSpecificFail(t *testing.T) {
	var tests = []struct {
		testName string
		hash     string
	}{
		{
			testName: "31ByteHashFF",
			hash:     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		},
		{
			testName: "31ByteHash00",
			hash:     "00000000000000000000000000000000000000000000000000000000000000",
		},
		{
			testName: "33ByteHashFF",
			hash:     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		},
		{
			testName: "33ByteHash00",
			hash:     "000000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			testName: "33ByteHash...FF00",
			hash:     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00",
		},
		{
			testName: "33ByteHash00FF...",
			hash:     "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		},
		{
			testName: "1ByteHash00",
			hash:     "00",
		},
		{
			testName: "1ByteHashFF",
			hash:     "FF",
		},
		{
			testName: "0ByteHash",
			hash:     "",
		},
	}

	client := &http.Client{}

	//Iterate over all tests
	for _, currTest := range tests {
		t.Run(currTest.testName, func(t *testing.T) {
			asserter := assert.New(t)
			requirer := require.New(t)

			//Create request
			hashBytes, err := hex.DecodeString(currTest.hash)
			requirer.NoError(err, "Failed to decode hex string for hash input.")
			req, err := createHashRequest(defaultClientAddress, defaultAuthToken, defaultUUID, hashBytes)
			requirer.NoError(err, "Failed to create hash request, aborting")

			//Do request
			resp, err := client.Do(req)
			requirer.NoErrorf(err, "Failed to do request: %v. \n Is the client started and reachable?", err)
			defer resp.Body.Close()

			//Check for error response (these tests should all fail, so we should not get a 200)
			body, err := ioutil.ReadAll(resp.Body)
			asserter.NoError(err, "Could not read response body")
			asserter.NotEqualf(200, resp.StatusCode, "Received '200 OK' for fail test.\nHash was: %v\nResponse body was: %v", hex.EncodeToString(hashBytes), hex.EncodeToString(body))

		})

	}
}

//TestHashSpecificSucceed tests cases with a specific hash as an input which must succeed
func TestHashSpecificSucceed(t *testing.T) {
	const nrOfTries = 3 // How often to send a packet before giving up (if backend does not reply with 200)

	var tests = []struct {
		testName string
		hash     string
	}{
		{
			testName: "HashFF",
			hash:     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		},
		{
			testName: "Hash00",
			hash:     "0000000000000000000000000000000000000000000000000000000000000000",
		},
	}

	client := &http.Client{}

	//Iterate over all tests
	for _, currTest := range tests {
		t.Run(currTest.testName, func(t *testing.T) {
			asserter := assert.New(t)
			requirer := require.New(t)

			//Create request
			hashBytes, err := hex.DecodeString(currTest.hash)
			requirer.NoError(err, "Failed to decode hex string for hash input.")
			req, err := createHashRequest(defaultClientAddress, defaultAuthToken, defaultUUID, hashBytes)
			requirer.NoError(err, "Failed to create hash request, aborting")

			tries := 0
			for tries < nrOfTries { //we will try until we reached max tries
				//Do request
				resp, err := client.Do(req)
				requirer.NoErrorf(err, "Failed to do request: %v. \n Is the client started and reachable?", err)
				defer resp.Body.Close()

				//Check response
				if resp.StatusCode == 200 { //everything was OK
					break //were done, break from retry loop
				} else { //unexpected response, retry, t.Logf info will only be shown if final error is asserted
					tries++
					body, err := ioutil.ReadAll(resp.Body)
					asserter.NoError(err, "Could not read response body")
					t.Logf("Try (%v/%v) for hash %v failed", tries, nrOfTries, hex.EncodeToString(hashBytes))
					t.Logf("Unexpected response code (%v) received", resp.StatusCode)
					t.Logf("Response body was: %v", hex.EncodeToString(body))

				}
			}
			//if we retried to often, request/hash is considered failing permanently -> ouput error
			if tries >= nrOfTries {
				t.Errorf("Max. tries was reached. Could not perform request with hash %v", hex.EncodeToString(hashBytes))
			}
		}) //End anonymous test function
	}
}
