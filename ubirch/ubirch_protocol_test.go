/*
 * Copyright (c) 2019 ubirch GmbH.
 *
 * ```
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ```
 */

package ubirch

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"github.com/google/uuid"
	"github.com/paypal/go.crypto/keystore"
	"log"
	"math/big"
	"testing"
)

// test fixtures
const (
	testName = "A"
	testUUID = "6eac4d0b-16e6-4508-8c46-22e7451ea5a1"
	testPriv = "8f827f925f83b9e676aeb87d14842109bee64b02f1398c6dcdd970d5d6880937"

	// expected messages
	expectedSigned = "9522c4106eac4d0b16e645088c4622e7451ea5a100c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc440"
)

// expected sequence of chained messages (contained signatures are placeholders only, ecdsa is not deterministic)
var expectedChained = [...]string{
	"9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c4204bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459ac440",
	"9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c420dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986c440",
	"9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c420084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5c440",
}

var context = &CryptoContext{
	Keystore: &keystore.Keystore{},
	Names:    map[string]uuid.UUID{},
}

var protocol = Protocol{
	Crypto:     context,
	Signatures: map[uuid.UUID][]byte{},
}

func (c *CryptoContext) GetLastSignature() ([]byte, error) {
	return nil, nil
}

func bytesToPrivateKey(bytes []byte) *ecdsa.PrivateKey {
	priv := new(ecdsa.PrivateKey)
	priv.D = new(big.Int)
	priv.D.SetBytes(bytes)
	priv.PublicKey.Curve = elliptic.P256()
	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(priv.D.Bytes())
	return priv
}

func init() {
	id := uuid.MustParse(testUUID)
	privBytes, err := hex.DecodeString(testPriv)
	if err != nil {
		panic(err)
	}
	err = context.storePrivateKey(testName, id, bytesToPrivateKey(privBytes))
	if err != nil {
		panic(err)
	}
}

func TestCreateSignedMessage(t *testing.T) {
	digest := sha256.Sum256([]byte{'1'})
	upp, err := protocol.Sign(testName, digest[:], Signed)
	if err != nil {
		t.Errorf("signing failed: %v", err)
	}
	log.Printf("E: %s", expectedSigned)
	log.Printf("R: %s", hex.EncodeToString(upp[:len(upp)-64]))
	if expectedSigned != hex.EncodeToString(upp[:len(upp)-64]) {
		t.Errorf("upp encoding wrong")
	}
}

func TestCreateChainedMessage(t *testing.T) {
	previousSignature := make([]byte, 64)
	for i := 0; i < 3; i++ {
		digest := sha256.Sum256([]byte{byte(i + 1)})
		upp, err := protocol.Sign(testName, digest[:], Chained)
		if err != nil {
			t.Errorf("signing failed: %v", err)
		}
		expected, _ := hex.DecodeString(expectedChained[i])
		copy(expected[22:22+64], previousSignature)
		previousSignature = upp[len(upp)-64:]
		//log.Printf("%d S: %s", i, hex.EncodeToString(previousSignature))
		log.Printf("%d E: (%d) %s", i, len(expected), hex.EncodeToString(expected))
		log.Printf("%d R: (%d) %s", i, len(upp[:len(upp)-64]), hex.EncodeToString(upp[:len(upp)-64]))
		if !bytes.Equal(expected, upp[:len(upp)-64]) {
			t.Errorf("chain: %d: upp encoding wrong", i)
			return
		}
	}
}
