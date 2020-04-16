package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
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

//Helper function for constant test JSON definitions which panics if the test JSON can't be marshaled to bytes
func mustMarshalJSON(v interface{}) []byte {
	bytes, err := json.Marshal(v)
	if err != nil {
		panic("Test case data could not be marshaled to JSON")
	}
	return bytes
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
	client := &http.Client{}
	asserter := assert.New(t)
	requirer := require.New(t)

	for currTest := 0; currTest < nrOfTests; currTest++ {
		t.Logf("Sending random hash %v/%v", currTest+1, nrOfTests) //This will only be shown in verbose mode or in case of error
		//Create request
		rand.Read(hashBytes) //generate new Hash for this request
		req, err := createHashRequest(defaultClientAddress, defaultAuthToken, defaultUUID, hashBytes)
		requirer.NoError(err, "Failed to create hash request, aborting")

		tries := 0              //reset tries counter
		for tries < nrOfTries { //we will try until we reached max tries
			//Do request
			resp, err := client.Do(req)
			requirer.NoErrorf(err, "Failed to do request: %v. \n Is the client started and reachable?", err)
			defer resp.Body.Close()

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
	}
}

//TestHashTableFail tests cases with a specific hash as an input which must fail
func TestHashTableFail(t *testing.T) {
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

//TestHashTableSucceed tests cases with a specific hash as an input which must succeed
func TestHashTableSucceed(t *testing.T) {
	const nrOfTries = 5 // How often to send a packet before giving up (if backend does not reply with 200)

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

//TestJSONTableFail tests cases with a specific JSON as an input which must fail
func TestJSONTableFail(t *testing.T) {
	var tests = []struct {
		testName  string
		JSONBytes []byte
	}{
		{
			testName:  "EmptyJSON",
			JSONBytes: []byte{},
		},
		{
			testName:  "InvalidJSON",
			JSONBytes: []byte("IamnotavalidJSON"),
		},
		{
			testName:  "UnbalancedBrackets",
			JSONBytes: []byte(`{"key":"value"`),
		},
		{
			testName:  "10MB-0x00-Bytes",
			JSONBytes: make([]byte, 10*1024*1024),
		},
	}

	client := &http.Client{}

	//Iterate over all tests
	for _, currTest := range tests {
		t.Run(currTest.testName, func(t *testing.T) {
			asserter := assert.New(t)
			requirer := require.New(t)

			//Create request
			req, err := createJSONRequest(defaultClientAddress, defaultAuthToken, defaultUUID, currTest.JSONBytes)
			requirer.NoError(err, "Failed to create JSON request, aborting")

			//Do request
			resp, err := client.Do(req)
			requirer.NoErrorf(err, "Failed to do request: %v. \n Is the client started and reachable?", err)
			defer resp.Body.Close()

			//Check for error response (these tests should all fail, so we should not get a 200)
			body, err := ioutil.ReadAll(resp.Body)
			asserter.NoError(err, "Could not read response body")
			asserter.NotEqualf(200, resp.StatusCode, "Received '200 OK' for fail test.\nJSON was: %v\nResponse body was: %v",
				string(currTest.JSONBytes),
				hex.EncodeToString(body))
		})

	}
}

//TestJSONTableSucceed tests cases with a specific JSON as an input which must succeed
func TestJSONTableSucceed(t *testing.T) {
	const nrOfTries = 5 // How often to send a packet before giving up (if backend does not reply with 200)

	var tests = []struct {
		testName  string
		JSONBytes []byte
	}{
		{
			testName:  "SimpleKeyValue1",
			JSONBytes: []byte(`{"key":"value"}`),
		},
		{
			testName:  "SimpleKeyValue2",
			JSONBytes: []byte(`{"key":1234}`),
		},
		{
			testName:  "SimpleKeyValue3",
			JSONBytes: []byte(`{"id":"ffffffff-ffff-ffff-ffff-ffffffffffff","store":"ubirch","value":3000}`),
		},
		{
			testName:  "StringArray",
			JSONBytes: mustMarshalJSON([]string{"apple", "peach", "pear"}),
		},
		{
			testName:  "Map",
			JSONBytes: mustMarshalJSON(map[string]int{"apple": 5, "lettuce": 7}),
		},
		{
			testName: "Struct",
			JSONBytes: mustMarshalJSON(
				struct {
					Key1 int
					Key2 string
				}{123, "value2"}),
		},
		{
			testName: "10MB-JSON",
			JSONBytes: mustMarshalJSON(
				struct {
					Key1 int
					Key2 []byte
				}{123, make([]byte, 10*1024*1024)}),
		},
	}

	client := &http.Client{}

	//Iterate over all tests
	for _, currTest := range tests {
		t.Run(currTest.testName, func(t *testing.T) {
			asserter := assert.New(t)
			requirer := require.New(t)

			//Create request
			req, err := createJSONRequest(defaultClientAddress, defaultAuthToken, defaultUUID, currTest.JSONBytes)
			requirer.NoError(err, "Failed to create JSON request, aborting")

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
					t.Logf("Try (%v/%v) for test %v failed", tries, nrOfTries, currTest.testName)
					t.Logf("Unexpected response code (%v) received", resp.StatusCode)
					t.Logf("Response body was (hex/string):\n%v\n%v", hex.EncodeToString(body), string(body))
				}
			}
			//if we retried to often, request/hash is considered failing permanently -> ouput error
			if tries >= nrOfTries {
				t.Errorf("Max. tries was reached. Could not perform request with JSON:\n%v", string(currTest.JSONBytes))
			}
		}) //End anonymous test function
	}
}

//TestJSONDataLength tests various length data input into the JSON endpoint
func TestJSONDataLength(t *testing.T) {
	const maxDataSize = 1030 // Largest []byte size to use for the JSON generation
	const nrOfTries = 5      // How often to send a packet before giving up (if backend does not reply with 200)

	client := &http.Client{}

	//Iterate over all sizes
	for dataSize := 0; dataSize <= maxDataSize; dataSize++ {
		t.Run("dataSize="+strconv.Itoa(dataSize), func(t *testing.T) {
			asserter := assert.New(t)
			requirer := require.New(t)

			dataBytes := make([]byte, dataSize)
			_, err := rand.Read(dataBytes) //fill data with random bytes
			requirer.NoError(err, "Could not get random bytes")
			JSONBytes, err := json.Marshal(dataBytes)
			requirer.NoError(err, "Marshaling data to JSON failed, aborting")
			t.Logf("JSON: %v", string(JSONBytes))
			t.Logf("len(JSON)=%v", len(JSONBytes))

			//Create request
			req, err := createJSONRequest(defaultClientAddress, defaultAuthToken, defaultUUID, JSONBytes)
			requirer.NoError(err, "Failed to create JSON request, aborting")

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
					t.Logf("Try (%v/%v) for data size %v failed", tries, nrOfTries, dataSize)
					t.Logf("Unexpected response code (%v) received", resp.StatusCode)
					t.Logf("Response body was (hex/string):\n%v\n%v", hex.EncodeToString(body), string(body))
				}
			}
			//if we retried to often, request/hash is considered failing permanently -> ouput error
			if tries >= nrOfTries {
				t.Errorf("Max. tries was reached. Could not perform request with JSON:\n%v", string(JSONBytes))
			}
		}) //End anonymous test function
	}
}
