package handlers

//func TestIdentityHandler_InitIdentities(t *testing.T) {
//	Identities := map[string]string{
//		"81A1A37D-8A4C-4A01-8689-8627193484E2": "authToken",
//		"E993DBDD-42F5-4B14-9BB5-2C568FBC22A5": "authToken",
//	}
//	ctrl := gomock.NewController(t)
//	extendedProtocol := mk.NewMockExtendedProtocols(ctrl)
//
//	extendedProtocol.EXPECT().
//		Exists(gomock.Any()).
//		Times(2).
//		Return(false, nil)
//	extendedProtocol.EXPECT().
//		GenerateKey().
//		Times(2).
//		Return([]byte(privateKeyPem), nil)
//	extendedProtocol.EXPECT().
//		GetPublicKeyFromPrivateKey(gomock.Eq([]byte(privateKeyPem))).
//		Times(2).
//		Return(nil, nil)
//	extendedProtocol.EXPECT().
//		SignatureLength().
//		Times(2).
//		Return(0)
//	extendedProtocol.EXPECT().
//		StartTransaction(gomock.Any()).
//		Times(2).
//		Return(nil, nil)
//	extendedProtocol.EXPECT().
//		StoreNewIdentity(gomock.Any(), gomock.Any()).
//		Times(2).
//		Return(nil)
//	extendedProtocol.EXPECT().
//		GetSignedKeyRegistration(gomock.Any(), gomock.Any()).
//		Times(2).
//		Return(nil, nil)
//	extendedProtocol.EXPECT().
//		GetCSR(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
//		Times(2).
//		Return(nil, nil)
//	extendedProtocol.EXPECT().
//		SubmitKeyRegistration(gomock.Any(), gomock.Any(), gomock.Any()).
//		Times(2).
//		Return(nil)
//	extendedProtocol.EXPECT().
//		SubmitCSR(gomock.Any(), gomock.Any()).
//		Times(2).
//		Return(nil)
//	extendedProtocol.EXPECT().
//		CloseTransaction(gomock.Any(), gomock.Any()).
//		Times(2).
//		Return(nil)
//
//	identityHandler := IdentityHandler{
//		Protocol:            extendedProtocol,
//		SubjectCountry:      "de",
//		SubjectOrganization: "ubrich",
//	}
//	err := identityHandler.InitIdentities(Identities)
//	require.NoError(t, err)
//}
//
//var privateKeyPem = `-----BEGIN PRIVATE KEY-----
//MHcCAQEEIBmhpZ+vjZEYXOY6s9iw540quY3/dDzqXjDWWGhCABLQoAoGCCqGSM49
//AwEHoUQDQgAE8BmXT8t+YTke5Gvfi6ZtUNwHNSTq98kxZJ4KKK71JwFUF/d1teVn
//RoNMizToRSBlncTsxv5XWqHMp5y26gfYpw==
//-----END PRIVATE KEY-----`
