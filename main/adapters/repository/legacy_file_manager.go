package repository

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-go/ubirch/v2"

	log "github.com/sirupsen/logrus"
)

const (
	keyFileName      = "keys.json"
	signatureDirName = "signatures"
	filePerm         = 0644
	dirPerm          = 0755

	contextFileName_Legacy = "protocol.json" // TODO: DEPRECATED
)

type FileManager struct {
	KeyFile           string
	SignatureDir      string
	EncryptedKeystore *ubirch.EncryptedKeystore
}

func NewFileManager(configDir string, secret []byte) (*FileManager, error) {
	f := &FileManager{
		KeyFile:           filepath.Join(configDir, keyFileName),
		SignatureDir:      filepath.Join(configDir, signatureDirName),
		EncryptedKeystore: ubirch.NewEncryptedKeystore(secret),
	}

	log.Debugf(" - keystore file: %s", f.KeyFile)
	log.Debugf(" - signature dir: %s", f.SignatureDir)

	err := f.portLegacyProtocolCtxFile(configDir)
	if err != nil {
		return nil, err
	}

	err = f.portLegacyKeystoreFile()
	if err != nil {
		return nil, err
	}

	err = f.loadKeys()
	if err != nil {
		return nil, err
	}

	ids, err := f.EncryptedKeystore.GetIDs()
	if err != nil {
		return nil, err
	}
	log.Infof("loaded %d keys from file system", len(ids))

	return f, nil
}

func (f *FileManager) GetPrivateKey(uid uuid.UUID) ([]byte, error) {
	return f.EncryptedKeystore.GetPrivateKey(uid)
}

func (f *FileManager) GetPublicKey(uid uuid.UUID) ([]byte, error) {
	return f.EncryptedKeystore.GetPublicKey(uid)
}

func (f *FileManager) GetSignature(uid uuid.UUID) ([]byte, error) {
	return os.ReadFile(f.signatureFile(uid))
}

func (f *FileManager) SetSignature(uid uuid.UUID, signature []byte) error {
	return os.WriteFile(f.signatureFile(uid), signature, filePerm)
}

func (f *FileManager) signatureFile(uid uuid.UUID) string {
	signatureFileName := uid.String() + ".bin"
	return filepath.Join(f.SignatureDir, signatureFileName)
}

func (f *FileManager) loadKeys() error {
	return loadFile(f.KeyFile, f.EncryptedKeystore.Keystore)
}

func loadFile(file string, dest interface{}) error {
	if _, err := os.Stat(file); os.IsNotExist(err) { // if file does not exist yet, return right away
		return nil
	}
	contextBytes, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		file = file + ".bck"
		contextBytes, err = os.ReadFile(filepath.Clean(file))
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
	return os.WriteFile(file, contextBytes, filePerm)
}

// this is here only for the purpose of backwards compatibility TODO: DEPRECATE
type legacyCryptoCtx struct {
	Keystore map[string]string
}

type legacyProtocolCtx struct {
	Crypto     legacyCryptoCtx
	Signatures map[uuid.UUID][]byte
}

func (f *FileManager) portLegacyProtocolCtxFile(configDir string) error {
	contextFileLegacy := filepath.Join(configDir, contextFileName_Legacy)

	if _, err := os.Stat(contextFileLegacy); os.IsNotExist(err) { // if file does not exist, return right away
		return nil
	}

	p := &legacyProtocolCtx{
		Crypto:     legacyCryptoCtx{Keystore: map[string]string{}},
		Signatures: map[uuid.UUID][]byte{},
	}

	// read legacy protocol context from persistent storage
	err := loadFile(contextFileLegacy, p)
	if err != nil {
		return fmt.Errorf("unable to load legacy protocol context: %v", err)
	}

	// persist loaded keys to new key storage
	err = persistFile(f.KeyFile, p.Crypto.Keystore)
	if err != nil {
		return fmt.Errorf("unable to persist keys: %v", err)
	}

	// persist loaded signatures to new signature storage
	err = f.persistSignatures(p.Signatures)
	if err != nil {
		return fmt.Errorf("unable to persist signatures: %v", err)
	}

	// delete legacy protocol ctx file + bckup
	err = os.Remove(contextFileLegacy)
	if err != nil {
		log.Warnf("unable to delete legacy protocol context file: %v", err)
	}
	err = os.Remove(contextFileLegacy + ".bck")
	if err != nil && !os.IsNotExist(err) {
		log.Warnf("unable to delete legacy protocol context backup file: %v", err)
	}

	return nil
}

func (f *FileManager) persistSignatures(signatures map[uuid.UUID][]byte) error {
	if _, err := os.Stat(f.SignatureDir); os.IsNotExist(err) {
		err = os.Mkdir(f.SignatureDir, dirPerm)
		if err != nil {
			return err
		}
	}

	for uid, signature := range signatures {

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

func (f *FileManager) portLegacyKeystoreFile() error {
	legacyKeystoreFile := &legacyCryptoCtx{Keystore: map[string]string{}}

	// read legacy protocol context from persistent storage
	err := loadFile(f.KeyFile, legacyKeystoreFile)
	if err != nil {
		return fmt.Errorf("unable to load legacy protocol context: %v", err)
	}

	if len(legacyKeystoreFile.Keystore) == 0 {
		return nil
	}

	// persist loaded keys to new key storage
	err = persistFile(f.KeyFile, legacyKeystoreFile.Keystore)
	if err != nil {
		return fmt.Errorf("unable to persist keys: %v", err)
	}

	return nil
}
