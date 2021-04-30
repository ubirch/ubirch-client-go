package ent

type Identity struct {
	Uid        string
	PrivateKey []byte
	PublicKey  []byte
	Signature  []byte
	AuthToken  string
}
