package handlers

import (
	"encoding/base64"
	"net/http"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	h "github.com/ubirch/ubirch-client-go/main/adapters/http_server"
)

var (
	testUuid         = uuid.UUID{0xaa, 0x9a, 0xbf, 0xf7, 0xc0, 0x0, 0x45, 0x7a, 0xaa, 0xb6, 0x18, 0xf6, 0x69, 0x0, 0xe6, 0x66}
	testAuth         = "123456"
	testSecret, _    = base64.StdEncoding.DecodeString("ZQJt1OC9+4OZtgZLLT9mX25BbrZdxtOQBjK4GyRF2fQ=")
	conf             = &config.Config{SecretBytes32: testSecret}
	testHash         = h.Sha256Sum{0x80, 0xc9, 0x83, 0xc2, 0xfa, 0x61, 0x75, 0x1b, 0x2f, 0x78, 0x42, 0xa3, 0xa3, 0x39, 0x34, 0xfc, 0xbe, 0xd1, 0xc4, 0x3a, 0xa2, 0x5c, 0xa3, 0xb6, 0x39, 0x5c, 0x12, 0xf5, 0x53, 0xe2, 0xf0, 0x5e}
	testSignature    = []byte{0xb6, 0x2b, 0xc0, 0x1a, 0xc9, 0xe5, 0xb1, 0xd8, 0x97, 0x73, 0x6f, 0xf9, 0x87, 0x7b, 0x43, 0x75, 0x3c, 0xb7, 0xbd, 0x57, 0xb1, 0xb0, 0x47, 0x7e, 0x87, 0xdc, 0x47, 0x34, 0x20, 0x25, 0x94, 0xf5, 0x4a, 0xfb, 0x78, 0x28, 0x3e, 0xf8, 0x9, 0xbf, 0x9f, 0x72, 0xbc, 0x5d, 0x55, 0x6f, 0x66, 0x5b, 0xb1, 0xff, 0x11, 0x7e, 0x59, 0x22, 0x1d, 0xe3, 0xea, 0x3a, 0xb3, 0x57, 0x3e, 0x5f, 0xe9, 0xd0}
	testPublicKey    = []byte{0x05, 0x0b, 0xd7, 0xfb, 0x9d, 0x9f, 0x3d, 0x17, 0x7d, 0x9f, 0x1c, 0x18, 0x0d, 0x1e, 0xe4, 0x7a, 0xe6, 0x53, 0xd6, 0x46, 0x19, 0xb9, 0x98, 0x9f, 0xa2, 0x76, 0x03, 0xfa, 0x18, 0xe3, 0x74, 0xc7, 0x71, 0x4f, 0x96, 0xe2, 0x2c, 0x61, 0xc8, 0x17, 0x9b, 0x1a, 0x10, 0x29, 0x45, 0x1d, 0x5c, 0xc6, 0xfc, 0x3e, 0xa9, 0x0d, 0x9b, 0x30, 0x39, 0xf6, 0x2b, 0x36, 0xe1, 0x3d, 0xa2, 0xc3, 0x7f, 0x3e}
	testPublicKeyPEM = []byte{0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x50, 0x55, 0x42, 0x4c, 0x49, 0x43, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x4d, 0x46, 0x6b, 0x77, 0x45, 0x77, 0x59, 0x48, 0x4b, 0x6f, 0x5a, 0x49, 0x7a, 0x6a, 0x30, 0x43, 0x41, 0x51, 0x59, 0x49, 0x4b, 0x6f, 0x5a, 0x49, 0x7a, 0x6a, 0x30, 0x44, 0x41, 0x51, 0x63, 0x44, 0x51, 0x67, 0x41, 0x45, 0x42, 0x51, 0x76, 0x58, 0x2b, 0x35, 0x32, 0x66, 0x50, 0x52, 0x64, 0x39, 0x6e, 0x78, 0x77, 0x59, 0x44, 0x52, 0x37, 0x6b, 0x65, 0x75, 0x5a, 0x54, 0x31, 0x6b, 0x59, 0x5a, 0x0a, 0x75, 0x5a, 0x69, 0x66, 0x6f, 0x6e, 0x59, 0x44, 0x2b, 0x68, 0x6a, 0x6a, 0x64, 0x4d, 0x64, 0x78, 0x54, 0x35, 0x62, 0x69, 0x4c, 0x47, 0x48, 0x49, 0x46, 0x35, 0x73, 0x61, 0x45, 0x43, 0x6c, 0x46, 0x48, 0x56, 0x7a, 0x47, 0x2f, 0x44, 0x36, 0x70, 0x44, 0x5a, 0x73, 0x77, 0x4f, 0x66, 0x59, 0x72, 0x4e, 0x75, 0x45, 0x39, 0x6f, 0x73, 0x4e, 0x2f, 0x50, 0x67, 0x3d, 0x3d, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x50, 0x55, 0x42, 0x4c, 0x49, 0x43, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a}
	testSignedUPP    = []byte{0x95, 0x22, 0xc4, 0x10, 0xaa, 0x9a, 0xbf, 0xf7, 0xc0, 0x00, 0x45, 0x7a, 0xaa, 0xb6, 0x18, 0xf6, 0x69, 0x00, 0xe6, 0x66, 0x00, 0xc4, 0x20, 0x80, 0xc9, 0x83, 0xc2, 0xfa, 0x61, 0x75, 0x1b, 0x2f, 0x78, 0x42, 0xa3, 0xa3, 0x39, 0x34, 0xfc, 0xbe, 0xd1, 0xc4, 0x3a, 0xa2, 0x5c, 0xa3, 0xb6, 0x39, 0x5c, 0x12, 0xf5, 0x53, 0xe2, 0xf0, 0x5f, 0xc4, 0x40, 0xf7, 0x49, 0x01, 0xb5, 0x35, 0x5b, 0x77, 0x8a, 0x9c, 0xb1, 0x02, 0xa5, 0x53, 0xf1, 0xad, 0xe1, 0x26, 0xa9, 0x30, 0xc6, 0x0f, 0xd0, 0xd9, 0xc7, 0xb9, 0x24, 0x58, 0x0d, 0x45, 0xd3, 0x05, 0x50, 0xb1, 0xb0, 0xc0, 0xe0, 0x38, 0x6d, 0x07, 0x0f, 0x1a, 0x48, 0x7e, 0xb3, 0x56, 0x98, 0x95, 0x71, 0x13, 0xda, 0x67, 0x1a, 0xa8, 0xd3, 0x3c, 0xe6, 0xd4, 0xf1, 0x63, 0xa0, 0xee, 0xa5, 0x51, 0xe5}
	testChainedUPP   = []byte{0x96, 0x23, 0xc4, 0x10, 0x7e, 0x41, 0xc4, 0x21, 0xac, 0xad, 0x46, 0xe5, 0x95, 0xf3, 0x20, 0x70, 0xcf, 0x78, 0x29, 0x2b, 0xc4, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc4, 0x20, 0x95, 0xd5, 0x80, 0x47, 0xc6, 0x72, 0xe, 0xb, 0xaa, 0x1e, 0xbf, 0xc5, 0xcc, 0xf4, 0xe7, 0xa4, 0x66, 0x68, 0xc2, 0x36, 0x32, 0x31, 0x4d, 0x6e, 0x2a, 0x82, 0xfb, 0x47, 0x7d, 0xa2, 0xc4, 0x32, 0xc4, 0x40, 0x1e, 0xa6, 0x34, 0x30, 0x38, 0x64, 0xa2, 0x28, 0xf4, 0x86, 0x5, 0x44, 0x23, 0xb9, 0xc5, 0x61, 0x70, 0x1b, 0x5c, 0x3c, 0x32, 0x96, 0xb2, 0x9a, 0xdc, 0x88, 0xd9, 0xd2, 0xde, 0x9, 0x43, 0xfd, 0xeb, 0xf2, 0xfc, 0x3c, 0xa3, 0x12, 0x94, 0xbd, 0x74, 0xc3, 0x2d, 0xac, 0xfe, 0x1e, 0x36, 0xa2, 0xb0, 0x3e, 0x9b, 0x1, 0xb8, 0x5e, 0xa3, 0x9a, 0x38, 0xfb, 0xf4, 0x2c, 0xd1, 0xa4, 0xf3, 0x3a}
	testBckndRespUPP = []byte{0x96, 0x23, 0xc4, 0x10, 0x10, 0xb2, 0xe1, 0xa4, 0x56, 0xb3, 0x4f, 0xff, 0x9a, 0xda, 0xcc, 0x8c, 0x20, 0xf9, 0x30, 0x16, 0xc4, 0x40, 0x1e, 0xa6, 0x34, 0x30, 0x38, 0x64, 0xa2, 0x28, 0xf4, 0x86, 0x5, 0x44, 0x23, 0xb9, 0xc5, 0x61, 0x70, 0x1b, 0x5c, 0x3c, 0x32, 0x96, 0xb2, 0x9a, 0xdc, 0x88, 0xd9, 0xd2, 0xde, 0x9, 0x43, 0xfd, 0xeb, 0xf2, 0xfc, 0x3c, 0xa3, 0x12, 0x94, 0xbd, 0x74, 0xc3, 0x2d, 0xac, 0xfe, 0x1e, 0x36, 0xa2, 0xb0, 0x3e, 0x9b, 0x1, 0xb8, 0x5e, 0xa3, 0x9a, 0x38, 0xfb, 0xf4, 0x2c, 0xd1, 0xa4, 0xf3, 0x3a, 0x0, 0xc4, 0x20, 0x2e, 0x33, 0x60, 0x93, 0x4f, 0xd0, 0x4e, 0x61, 0x8f, 0x49, 0xcb, 0x19, 0x3c, 0xbb, 0x42, 0xf8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc4, 0x40, 0x99, 0xc9, 0xd9, 0x2e, 0xd, 0xf1, 0x19, 0xdf, 0x11, 0x3, 0xe6, 0x2c, 0xe4, 0x25, 0x60, 0xd8, 0x2f, 0x3f, 0x5b, 0x3, 0x6a, 0x38, 0x9f, 0xc7, 0x1e, 0x23, 0xf3, 0x54, 0x59, 0x6c, 0x51, 0xb0, 0x3, 0x44, 0x27, 0xad, 0xc1, 0x6a, 0x9c, 0xf9, 0x12, 0x2b, 0x1d, 0x21, 0xfc, 0xe5, 0x2a, 0xf6, 0xaf, 0x63, 0x98, 0xff, 0xd8, 0xdc, 0x4b, 0xe3, 0x10, 0x31, 0x12, 0x4e, 0xc, 0x8e, 0x76, 0x52}
	testRequestID    = "2e336093-4fd0-4e61-8f49-cb193cbb42f8"
	testBckndResp    = h.HTTPResponse{
		StatusCode: http.StatusOK,
		Header:     http.Header{"test": []string{"header"}},
		Content:    testBckndRespUPP,
	}
	testVerificationResp = []byte("{\"upp\":\"lSLEEKqav/fAAEV6qrYY9mkA5mYAxCCAyYPC+mF1Gy94QqOjOTT8vtHEOqJco7Y5XBL1U+LwXsRAGhsRO1aNd17o3ur81fpT1CrU/CwJZavgV0AvkQiJjhgQF5fiamxBvRcuQm/PoOVBYIbWDftRafG99yP76VlHCQ==\",\"prev\":null,\"anchors\":null}")
	testVerificationUPP  = []byte{0x95, 0x22, 0xc4, 0x10, 0xaa, 0x9a, 0xbf, 0xf7, 0xc0, 0x00, 0x45, 0x7a, 0xaa, 0xb6, 0x18, 0xf6, 0x69, 0x00, 0xe6, 0x66, 0x00, 0xc4, 0x20, 0x80, 0xc9, 0x83, 0xc2, 0xfa, 0x61, 0x75, 0x1b, 0x2f, 0x78, 0x42, 0xa3, 0xa3, 0x39, 0x34, 0xfc, 0xbe, 0xd1, 0xc4, 0x3a, 0xa2, 0x5c, 0xa3, 0xb6, 0x39, 0x5c, 0x12, 0xf5, 0x53, 0xe2, 0xf0, 0x5e, 0xc4, 0x40, 0x1a, 0x1b, 0x11, 0x3b, 0x56, 0x8d, 0x77, 0x5e, 0xe8, 0xde, 0xea, 0xfc, 0xd5, 0xfa, 0x53, 0xd4, 0x2a, 0xd4, 0xfc, 0x2c, 0x09, 0x65, 0xab, 0xe0, 0x57, 0x40, 0x2f, 0x91, 0x08, 0x89, 0x8e, 0x18, 0x10, 0x17, 0x97, 0xe2, 0x6a, 0x6c, 0x41, 0xbd, 0x17, 0x2e, 0x42, 0x6f, 0xcf, 0xa0, 0xe5, 0x41, 0x60, 0x86, 0xd6, 0x0d, 0xfb, 0x51, 0x69, 0xf1, 0xbd, 0xf7, 0x23, 0xfb, 0xe9, 0x59, 0x47, 0x09}
	testKeyRegs          = []ubirch.SignedKeyRegistration{{PubKeyInfo: ubirch.KeyRegistration{PubKey: base64.StdEncoding.EncodeToString(testPublicKey)}}}
)