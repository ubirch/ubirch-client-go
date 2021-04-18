package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
)

const (
	keyDirName       = "keys"
	signatureDirName = "signatures"
	authTokenDirName = "tokens"
	filePerm         = 0644
	dirPerm          = 0755

	contextFileName_Legacy = "protocol.json" // TODO: DEPRECATED
	keyFileName_Legacy     = "keys.json"     // TODO: DEPRECATED
)

type FileManager struct {
	keyDir            string
	signatureDir      string
	authTokenDir      string
	EncryptedKeystore *ubirch.EncryptedKeystore
	Signatures        map[uuid.UUID][]byte // this is here only for the purpose of backwards compatibility TODO: DEPRECATED
}

func (f *FileManager) StartTransaction(uid uuid.UUID) error {
	panic("implement me")
}

func (f *FileManager) EndTransaction(uid uuid.UUID) error {
	panic("implement me")
}

func (f *FileManager) DeleteIdentity(uid uuid.UUID) error {
	panic("implement me")
}

// Ensure FileManager implements the ContextManager interface
var _ ContextManager = (*FileManager)(nil)

func NewFileManager(configDir string, secret []byte) (*FileManager, error) {
	f := &FileManager{
		keyDir:            filepath.Join(configDir, keyDirName),
		signatureDir:      filepath.Join(configDir, signatureDirName),
		authTokenDir:      filepath.Join(configDir, authTokenDirName),
		EncryptedKeystore: ubirch.NewEncryptedKeystore(secret),
		Signatures:        map[uuid.UUID][]byte{},
	}

	err := initDirectories([]string{f.keyDir, f.signatureDir, f.authTokenDir})
	if err != nil {
		return nil, err
	}

	log.Info("protocol context will be stored in local file system")
	log.Debugf(" - keystore dir: %s", f.keyDir)
	log.Debugf(" - signature dir: %s", f.signatureDir)
	log.Debugf(" - token dir: %s", f.authTokenDir)

	err = f.portLegacyProtocolCtxFile(configDir)
	if err != nil {
		return nil, err
	}

	return f, nil
}

func (f *FileManager) GetPrivateKey(uid uuid.UUID) ([]byte, error) {
	return ioutil.ReadFile(f.privateKeyFile(uid))
}

func (f *FileManager) SetPrivateKey(uid uuid.UUID, key []byte) error {
	return ioutil.WriteFile(f.privateKeyFile(uid), key, filePerm)
}

func (f *FileManager) GetPublicKey(uid uuid.UUID) ([]byte, error) {
	return ioutil.ReadFile(f.publicKeyFile(uid))
}

func (f *FileManager) SetPublicKey(uid uuid.UUID, key []byte) error {
	return ioutil.WriteFile(f.publicKeyFile(uid), key, filePerm)
}

func (f *FileManager) GetSignature(uid uuid.UUID) ([]byte, error) {
	return ioutil.ReadFile(f.signatureFile(uid))
}

func (f *FileManager) SetSignature(uid uuid.UUID, signature []byte) error {
	return ioutil.WriteFile(f.signatureFile(uid), signature, filePerm)
}

func (f *FileManager) GetAuthToken(uid uuid.UUID) (string, error) {
	tokenBytes, err := ioutil.ReadFile(f.authTokenFile(uid))
	if err != nil {
		return "", err
	}

	return string(tokenBytes), nil
}

func (f *FileManager) SetAuthToken(uid uuid.UUID, authToken string) error {
	return ioutil.WriteFile(f.authTokenFile(uid), []byte(authToken), filePerm)
}

func (f *FileManager) Close() error {
	return nil
}

func (f *FileManager) privateKeyFile(uid uuid.UUID) string {
	privateKeyFileName := "_" + uid.String() + ".bin"
	return filepath.Join(f.keyDir, privateKeyFileName)
}

func (f *FileManager) publicKeyFile(uid uuid.UUID) string {
	publicKeyFileName := uid.String() + ".bin"
	return filepath.Join(f.keyDir, publicKeyFileName)
}

func (f *FileManager) signatureFile(uid uuid.UUID) string {
	signatureFileName := uid.String() + ".bin"
	return filepath.Join(f.signatureDir, signatureFileName)
}

func (f *FileManager) authTokenFile(uid uuid.UUID) string {
	authTokenFileName := uid.String() + ".bin"
	return filepath.Join(f.authTokenDir, authTokenFileName)
}

func initDirectories(directories []string) error {
	for _, dir := range directories {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			err = os.Mkdir(dir, dirPerm)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func loadFile(file string, dest interface{}) error {
	if _, err := os.Stat(file); os.IsNotExist(err) { // if file does not exist yet, return right away
		return nil
	}
	contextBytes, err := ioutil.ReadFile(file)
	if err != nil {
		file = file + ".bck"
		contextBytes, err = ioutil.ReadFile(file)
		if err != nil {
			return err
		}
	}
	err = json.Unmarshal(contextBytes, dest)
	if err != nil {
		if strings.HasSuffix(file, ".bck") {
			return err
		} else {
			return loadFile(file+".bck", dest)
		}
	}
	return nil
}

func persistFile(file string, source interface{}) error {
	if _, err := os.Stat(file); !os.IsNotExist(err) { // if file already exists, create a backup
		err = os.Rename(file, file+".bck")
		if err != nil {
			log.Warnf("unable to create backup file for %s: %v", file, err)
		}
	}
	contextBytes, _ := json.MarshalIndent(source, "", "  ")
	return ioutil.WriteFile(file, contextBytes, filePerm)
}

// this is here only for the purpose of backwards compatibility TODO: DEPRECATED
func (f *FileManager) portLegacyProtocolCtxFile(configDir string) error {
	contextFile_Legacy := filepath.Join(configDir, contextFileName_Legacy)
	keyFile_Legacy := filepath.Join(configDir, keyFileName_Legacy)

	if _, err := os.Stat(contextFile_Legacy); os.IsNotExist(err) { // if file does not exist, return right away
		return nil
	}

	// read legacy protocol context from persistent storage
	err := loadFile(contextFile_Legacy, &f)
	if err != nil {
		return fmt.Errorf("unable to load legacy protocol context: %v", err)
	}

	// read legacy key store from persistent storage
	err = loadFile(keyFile_Legacy, &f.EncryptedKeystore)
	if err != nil {
		return fmt.Errorf("unable to load legacy key store: %v", err)
	}

	// persist loaded keys to new key storage
	err = f.persistKeys()
	if err != nil {
		return fmt.Errorf("unable to persist keys: %v", err)
	}

	// persist loaded signatures to new signature storage
	err = f.persistSignatures()
	if err != nil {
		return fmt.Errorf("unable to persist signatures: %v", err)
	}

	// delete legacy protocol ctx file + bckup
	err = os.Remove(contextFile_Legacy)
	if err != nil {
		log.Warnf("unable to delete legacy protocol context file: %v", err)
	}
	err = os.Remove(contextFile_Legacy + ".bck")
	if err != nil {
		log.Warnf("unable to delete legacy protocol context backup file: %v", err)
	}

	// delete legacy key file + bckup
	err = os.Remove(keyFile_Legacy)
	if err != nil {
		log.Warnf("unable to delete legacy key file: %v", err)
	}
	err = os.Remove(keyFile_Legacy + ".bck")
	if err != nil {
		log.Warnf("unable to delete legacy key backup file: %v", err)
	}

	return nil
}

// this is here only for the purpose of backwards compatibility TODO: DEPRECATED
func (f *FileManager) persistKeys() error {
	for name, encryptedKey := range *f.EncryptedKeystore.Keystore {

		// todo sanity check?

		keyFileName := name + ".bin"
		keyFile := filepath.Join(f.keyDir, keyFileName)
		err := ioutil.WriteFile(keyFile, []byte(encryptedKey), filePerm)
		if err != nil {
			return err
		}
	}
	return nil
}

// this is here only for the purpose of backwards compatibility TODO: DEPRECATED
func (f *FileManager) persistSignatures() error {
	for uid, signature := range f.Signatures {

		if len(signature) != 64 {
			return fmt.Errorf("invalid signature length: expected 64, got %d", len(signature))
		}

		err := f.SetSignature(uid, signature)
		if err != nil {
			return err
		}
	}
	return nil
}
