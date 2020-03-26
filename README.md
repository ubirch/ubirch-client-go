# ubirch-client

The ubirch client allows you to quickly integrate the ubirch platform,
including the anchoring of information into public blockchains, into
your project.

It provides HTTP and UDP endpoints for sending either hashes that will be
anchored, or information to be hashed and subsequently anchored.

## UDP Endpoint


## HTTP Endpoint
UDP client example that reads messages from multiple devices
and creates ubirch-protocol secured messages.

This server handles keys and state.

The hashes are generated using SHA256 for the whole UDP payload.

## Build
A `Makefile` is provided to aid compiling and creating an executable for
the target architecture, it supports building x86 and ARM binaries, as well
as amd64 and ARM docker images.

## Install
If you want to use a database instead of configuration files, make sure
to apply the [database schema](main/schema.sql), as the application will
not create it itself on first run.



* build for ARM: run `make`
* copy `start.sh`, `main/ubirch-go-client`, and the `config.json` the target machine
* run `screen ./start.sh` (if it fails, use root or fix screen)
  - to exit screen presse `Ctrl-a d`
  - to reattach to the session, run `screen -R`

The output looks somewhat like this (started and stopped after first packet):
<details>
  <summary>Click to expand!</summary>

  ```
  2019/10/04 10:29:03 configuration found
  2019/10/04 10:29:03 loaded protocol context
  2019/10/04 10:29:03 1 certificates, 1 signatures
  2019/10/04 10:29:03 UDP server up and listening on :15001
  2019/10/04 10:29:05 received 127.0.0.1:35919: 9a47022cff09478ba68a1b3686a2f6f1e30708190d1013b66d0100000000
  2019/10/04 10:29:05 CERT [{"pubKeyInfo":{"algorithm":"ecdsa-p256v1","created":"2019-10-04T06:35:27.412Z","hwDeviceId":"9a47022c-ff09-478b-a68a-1b3686a2f6f1",  "pubKey":"o71ufIY0rP4GXQELZcXlm6t2s/LB29jzGfmheG3q8dJecxrGc/bqIODYcfROx6ofgunyarvG4lFiP+7p18qZ44==","pubKeyId":"o71ufIY0rP4GXQELZcXlm6t2s/LB29jzGfmheG3q8dJecxrGc/  bqIODYcfROx6ofgunyarvG4lFiP+7p18qZ44==","validNotAfter":"2020-10-03T06:35:27.412Z","validNotBefore":"2019-10-04T06:35:27.412Z"},"signature":"WQ/xDF7LVU/  CVFzqGwopleefBe5xMLFrnkyEUzE08s0pxZgbtudReaWw70FSPvf2f83kgMvd5gfLNBd1V3AG2g=="}]
  2019/10/04 10:29:05 9a47022c-ff09-478b-a68a-1b3686a2f6f1: registered key: (524) {"pubKeyInfo":{"algorithm":"ecdsa-p256v1","created":"2019-10-04T06:35:27.412Z",  "hwDeviceId":"9a47078c-ff09-478b-a68a-1b3686a2f6f1","pubKey":"o71ufIY0rP4GXQELZcXlm6t2s/LB29jzGfmheG3q8dJecxrGc/bqIODYcfROx6ofgunyarvG4lFiP+7p18qZqg==",  "pubKeyId":"o71ufIY0rP4GXQELZcXlm6t2s/LB29jzGfmheG3q8dJecxrGc/bqIODYcfROx6ofgunyarvG4lFiP+7p18qZqg==","validNotAfter":"2020-10-03T06:35:27.412Z",  "validNotBefore":"2019-10-04T06:35:27.412Z"},"signature":"WQ/xDF7LVU/CVFzqGwopleefBe5xMLFrnkyEUzE08s0pxZgbtudReaWw70FSPvf2f83kgMvd5gfLNBd1V3AGng=="}
  2019/10/04 10:29:05 9a47022c-ff09-478b-a68a-1b3686a2f6f1: hash RqIUM3vdS85IVfLYah/x0ebgssk648thMG+IVG0I6FQ=   (46a214337bdd4bce4855f2d86a1ff1d1e6e0b2c93ae3cb61306f88546d08e854)
  2019/10/04 10:29:05 9a47022c-ff09-478b-a68a-1b3686a2f6f1: UPP   9623c4109a47078cff09478ba68a1b3686a2f6f1c440ce2e42103c7fa58b477ea411c1abdbb90b80505496380f650f94a4c4cd4e0dd198a65e8f5d9fafb37fa16ae0355570e302e331bd74df7085f55c7eaf  cc4523f800c42046a214337bdd4bce4855f2d86a1ff1d1e6e0b2c93ae3cb61306f88546d08e854c440281dda50dc9b257c3ab4084c02ca28ba5596058fcef8dbe4e7c8f08f7eaafc298ec51cb9c99279af53  8b337893a3095149cfc47a098c4ca173dd23d96917ec75
  2019/10/04 10:29:05 self verification: <nil>: (error: msgpack decode error [pos 0]: cannot decode into value of kind: struct, type: ubirch.chained, ubirch.chained  {Version:0x0, Uuid:uuid.UUID{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, PrevSignature:[]uint8(nil), Hint:0x0, Payload:[]uint8  (nil), Signature:[]uint8(nil)})
  2019/10/04 10:29:06 9a47078c-ff09-478b-a68a-1b3686a2f6f1: "\x96#\xc4\x10\x9d<x\xff\"\xf3DA\xa5х\xc66Ԇ\xff\xc4@\xce.  B\x10<\u007f\xa5\x8bG~\xa4\x11\xc1\xab۹\v\x80PT\x968\x0fe\x0f\x94\xa4\xc4\xcdN\rј\xa6^\x8f]  \x9f\xaf\xb3\u007f\xa1j\xe05Up\xe3\x02\xe31\xbdt\xdfp\x85\xf5\\~\xaf\xccE#\xf8\x00\x81\xa7message\xbfyour request has been submitted\xc4@\x96\xf0\x88\x8d\x8do;  \xaf\xa2\x9b%\xd1{\x9b\t*+H\x86\xbea\x81\vS2S>\a\x14|q\xedUMG\x8f\xd5\xcaRx\xcb{\xf7\xe2\xec\x14\xd2T\x99b\x89A\x92\xc2\xe0\xbd̗\\$J\xf0\a\x04"
  2019/10/04 10:29:09 interrupt
  2019/10/04 10:29:09 finishing handler
  2019/10/04 10:29:09 saved protocol context
  ```
</details>

### Configuration
**NOTE**: The configuration from console.demo.ubirch.com sets the msgpack endpoint for 
  key registration. **Remove the `/mpack` from the end of the keyService URL!**

#### Via file
If the `UBIRCH_AUTH` env variable is unset or empty, and the `config.json`
file exists in the current working dir, the configuration will be read from
it.

#### Via env
The service can be configured via environment variables.
you can see the [example.env](main/example.env) as a starting point.

###### `UBIRCH_AUTH`
contains the auth type (most of the cases this will be "ubirch") 
###### `UBIRCH_KEYSERVICE`
contains the URL to the keyservice (eg. "https://key.demo.ubirch.com/api/keyService/v1/pubkey")
###### `UBIRCH_VERIFYSERVICE`
contains the URL to the verification service (eg. "https://verify.demo.ubirch.com/api/upp")
###### `UBIRCH_NIOMON`
contains the URL to the niomon service (eg. "https://niomon.demo.ubirch.com") 
###### `UBIRCH_INTERFACE_RXCERT`
(eg. "localhost:15001")
###### `UBIRCH_INTERFACE_RXVERIFY`
(eg. "localhost:15002")
###### `UBIRCH_INTERFACE_TXVERIFY`
(eg. "localhost:15000")
###### `UBIRCH_AUTH_MAP`
contains the auth map, which is a mapping from a user UUID to both a key and a auth token.
The format of this string is:

```json
{"9080559e-6f62-4122-884a-7a2471a3f635": ["rT7IGJ4zvvvGVN40bIAmGDTyKYq/8gCXqs+vBf3rTLc=", "0f4b2a18-c18d-4bf1-b723-729793521726"]}
```

* the first uuid is the client UUID registered with the [ubirch-console](https://console.demo.ubirch.com/).
* the base64 encoded string is a ECDSA secp256k1 key used for signing the UPPs.
* the last uuid is the auth-token for the client, as generated by the ubirch console.

### Run in Docker container
We provided a multi-arch Docker image that runs on amd64 as well as arm64 architecture. To start it, run:

```
docker pull ubirch/ubirch-client:latest
docker run -v $(pwd)/:/data/ --network=host ubirch/ubirch-client:latest .
```

### Message format
The expected payload of the UDP packets or HTTP post requests that are sent to the client starts with the device UUID (16 byte)
followed by any data in binary format.

```
4f6b64a7a5c9483786c00d32bc8e03c080d1a6763192d01500003fc93178a59b..
|<           UUID             >||< timestamp  >||<     misc     
|          (16 byte)           ||   (8 byte)   ||    (X byte)
```

The signer receives a message, seals its hash value in a UPP (Ubirch Protocol Package) which is sent to the Ubirch backend.

The verifier also calculates the hash over the message and checks for it in the Ubirch backend. If the hash exists in the backend,
the verifier appends a byte to the original message to indicate the verification success or failure and sends it to the UDP port.

The possible values are:

	OkVerified         = 0x00
	ErrUuidInvalid     = 0xE0
	ErrUppNotFound     = 0xE1
	ErrKeyNotFound     = 0xE2
	ErrSigFailed       = 0xF0
	ErrSigInvalid      = 0xF1
	ErrUppDecodeFailed = 0xF2
	ErrHashMismatch    = 0xF3
	
The successfully verified message of the example would then look like this:
```
4f6b64a7a5c9483786c00d32bc8e03c080d1a6763192d01500003fc93178a59b00
|<           UUID             >||< timestamp  >||<      misc    >|
|          (16 byte)           ||   (8 byte)   ||     (9 byte)   |
```

### Testing
There is a python script [`simulation/simulate_http.py`](simulation/simulate_http.py)
that reads data line for line from a text file and sends each line as http
post requests to the `http://localhost:8080/sign` endpoint. 

If the script is run without any command line arguments, it will read the
input data from [`simulation/plc-a-data.txt`](simulation/plc-a-data.txt). 
Alternatively, an input file can be passed as command line argument. For example:

    $ python ./simulation/simulate_http.py "simulation/my-test-input-file.txt"
    
The input file should contain the data for http requests to the client in
hex format. Each line starts with the UUID of the sender followed by any
other data (see [Message format](#message-format)).

## Copyright

```
Copyright (c) 2019 ubirch GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

Authors: Matthias L. Jugel, Waldemar Grünwald, Roxana Meixner