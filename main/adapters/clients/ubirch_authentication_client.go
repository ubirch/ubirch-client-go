// Copyright (c) 2019-2020 ubirch GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package clients

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	h "github.com/ubirch/ubirch-client-go/main/adapters/http_server"
	prom "github.com/ubirch/ubirch-client-go/main/prometheus"
)

type AuthenticationServiceClient struct {
	AuthServiceURL     string
	AuthServiceTimeout time.Duration
}

func (c *AuthenticationServiceClient) SendToAuthService(uid uuid.UUID, auth string, upp []byte) (h.HTTPResponse, error) {
	timer := prometheus.NewTimer(prom.UpstreamResponseDuration)
	defer timer.ObserveDuration()

	return sendRequest(http.MethodPost, c.AuthServiceURL, upp, ubirchHeader(uid, auth), c.AuthServiceTimeout)
}

func ubirchHeader(uid uuid.UUID, auth string) map[string]string {
	return map[string]string{
		"x-ubirch-hardware-id": uid.String(),
		"x-ubirch-auth-type":   "ubirch",
		"x-ubirch-credential":  base64.StdEncoding.EncodeToString([]byte(auth)),
	}
}
