package main

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"

	"github.com/fxamacker/cbor/v2" // imports as package "cbor"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
)

const (
	COSE_Kid_Label     = 4            // key identifier label (Common COSE Headers Parameters: https://cose-wg.github.io/cose-spec/#rfc.section.3.1)
	COSE_Sign1_Tag     = 18           // CBOR tag TBD7 identifies tagged COSE_Sign1 structure (https://cose-wg.github.io/cose-spec/#rfc.section.4.2)
	COSE_Sign1_Context = "Signature1" // signature context identifier for COSE_Sign1 structure (https://cose-wg.github.io/cose-spec/#rfc.section.4.4)

)

var ProtectedHeaderAlgES256 = []byte{0xA1, 0x01, 0x26} // {"alg": "ES256"}

// 	COSE_Sign1 = [
// 		Headers,
//		payload : bstr / nil,
//		signature : bstr
//	]
// https://cose-wg.github.io/cose-spec/#rfc.section.4.2
type COSE_Sign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[interface{}]interface{}
	Payload     []byte
	Signature   []byte
}

//	Sig_structure = [
// 		context : "Signature1",
//		body_protected : serialized_map,
//		external_aad : bstr,
//		payload : bstr
//	]
// https://cose-wg.github.io/cose-spec/#rfc.section.4.4
type Sig_structure struct {
	_               struct{} `cbor:",toarray"`
	Context         string
	ProtectedHeader []byte
	External        []byte
	Payload         []byte
}

type CoseSigner struct {
	cryptoCtx ubirch.Crypto
	encMode   cbor.EncMode
}

func NewCoseSigner(cryptoCtx ubirch.Crypto) *CoseSigner {
	encMode, err := initCBOREncMode()
	if err != nil {
		log.Panic(err) // todo
	}

	return &CoseSigner{
		cryptoCtx: cryptoCtx,
		encMode:   encMode,
	}
}

func (c *CoseSigner) Sign(msg HTTPRequest) HTTPResponse {
	log.Infof("%s: sign CBOR hash: %s", msg.ID, base64.StdEncoding.EncodeToString(msg.Hash[:]))

	coseBytes, err := c.getSignedCOSE(msg.ID, msg.Hash)
	if err != nil {
		log.Errorf("%s: could not create signed COSE: %v", msg.ID, err)
		return errorResponse(http.StatusInternalServerError, "")
	}
	log.Debugf("%s: signed COSE: %x", msg.ID, coseBytes)

	return HTTPResponse{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Content:    coseBytes,
	}
}

func (c *CoseSigner) getSignedCOSE(id uuid.UUID, hash [32]byte) ([]byte, error) {
	/*
		* https://cose-wg.github.io/cose-spec/#rfc.section.4.2

			The COSE_Sign1 structure is used when only one signature is going to be placed on a message.

			The structure can be encoded either tagged or untagged depending on the context it will be used in.
			A tagged COSE_Sign1 structure is identified by the CBOR tag TBD7. The CDDL fragment that represents this is:

			COSE_Sign1_Tagged = #6.18(COSE_Sign1)	# [18	cose-sign1	COSE_Sign1	COSE Single Signer Data Object]

			The COSE_Sign1 structure is a CBOR array. The fields of the array in order are:

			protected	as described in Section 3.
			unprotected	as described in Section 3.
			payload	    as described in Section 4.1.
			signature	contains the computed signature value. The type of the field is a bstr.

			The CDDL fragment that represents the above text for COSE_Sign1 follows.

			COSE_Sign1 = [
			    Headers,
			    payload : bstr / nil,
			    signature : bstr
			]

			* example: https://cose-wg.github.io/cose-spec/#Sign1_Examples

		* https://cose-wg.github.io/cose-spec/#rfc.section.3

				Headers = (
					protected : serialized_map,		# (b'\xA1\x01\x26')	=> {1: -7} => {"alg": "ES256"}
					unprotected : header_map		# \xA1\x04\x42\x31\x31 => {4: b'\x31\x31'} => {"kid": "11"}
				)

		* https://cose-wg.github.io/cose-spec/#rfc.section.4.4

			In order to create a signature, a well-defined byte stream is needed.
			The Sig_structure is used to create the canonical form.
			A Sig_structure is a CBOR array.

			The fields of the Sig_structure for COSE_Sign1 in order are:

			1. A text string identifying the context of the signature:
				"Signature1" for signatures using the COSE_Sign1 structure.

			2. The protected attributes from the body structure encoded in a bstr type.

			3. The protected attributes from the application encoded in a bstr type.
				If this field is not supplied, it defaults to a zero length binary string.

			4.The payload to be signed encoded in a bstr type.

			The CDDL fragment that describes the above text is:

				Sig_structure = [
					context : "Signature1",
					body_protected : serialized_map,	# (b'\xA1\x01\x26')	=> {1: -7}
					external_aad : empty bstr,			# (b'')
					payload : bstr						# (b'payload bytes')
				]

		* How to compute a signature:

			1. Create a Sig_structure and populate it with the appropriate fields.

			2. Create the value ToBeSigned by encoding the Sig_structure to a byte string, using the encoding described in Section 14.

			3. Call the signature creation algorithm passing in K (the key to sign with), alg (the algorithm to sign with), and ToBeSigned (the value to sign).

			4. Place the resulting signature value in the 'signature' field of the array.


			sig_structure = ['Signature1', b'\xA1\x01\x26', b'', b'payload bytes']
			toBeSigned = SHA256_hash(CBOR_encode(sig_structure))
			signature = ECDSA_sign(toBeSigned)
			COSE_Sign1 = [b'\xA1\x01\x26', {4: b'<uuid>'}, b'payload bytes', signature]

	*/

	// create ES256 signature
	signatureBytes, err := c.cryptoCtx.SignHash(id, hash[:])
	if err != nil {
		return nil, err
	}

	// create COSE_Sign1 object
	coseSign1 := &COSE_Sign1{
		Protected:   ProtectedHeaderAlgES256,
		Unprotected: map[interface{}]interface{}{COSE_Kid_Label: id[:]},
		Payload:     []byte{},
		Signature:   signatureBytes,
	}

	// encode COSE_Sign1 object with tag
	return c.encMode.Marshal(cbor.Tag{Number: COSE_Sign1_Tag, Content: coseSign1})
}

func initCBOREncMode() (cbor.EncMode, error) {
	encOpt := cbor.EncOptions{
		IndefLength: cbor.IndefLengthForbidden, // no streaming
		Sort:        cbor.SortCanonical,        // sort map keys
	}
	return encOpt.EncMode()
}

// GetSigStructDigest creates the SHA256 hash of a CBOR serialized signature structure
// containing given payload.
// Implements step 1 + 2 of the "How to compute a signature"-instructions
// from https://cose-wg.github.io/cose-spec/#rfc.section.4.4 (Signing and Verification Process)
func (c *CoseSigner) GetSigStructDigest(payload []byte) ([32]byte, error) {
	sigStruct := &Sig_structure{
		Context:         COSE_Sign1_Context,
		ProtectedHeader: ProtectedHeaderAlgES256,
		External:        []byte{}, // empty
		Payload:         payload,
	}

	toBeSigned, err := c.encMode.Marshal(sigStruct)
	if err != nil {
		return [32]byte{}, err
	}

	return sha256.Sum256(toBeSigned), nil
}
