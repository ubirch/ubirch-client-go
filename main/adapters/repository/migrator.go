package repository

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ubirch/ubirch-client-go/main/config"
	"github.com/ubirch/ubirch-client-go/main/ent"

	log "github.com/sirupsen/logrus"
)

func Migrate(c *config.Config) error {
	ctxManager, err := GetContextManager(c)
	if err != nil {
		return err
	}

	dm, ok := ctxManager.(*DatabaseManager)
	if !ok {
		return fmt.Errorf("context migration only supported in direction file to database. " +
			"Please set a DSN for a postgreSQL or SQLite database in the configuration")
	}

	for i := 0; i < 10; i++ {
		err = dm.IsReady()
		if err != nil {
			log.Warn(err)
			time.Sleep(3 * time.Second)
			continue
		}
		break
	}
	if err != nil {
		return err
	}

	// todo make sure context is not already migrated

	p, err := NewExtendedProtocol(dm, c)
	if err != nil {
		return err
	}

	err = migrateIdentities(c, p)
	if err != nil {
		return fmt.Errorf("could not migrate file-based context to database: %v", err)
	}

	log.Infof("successfully migrated file-based context to database")

	cleanUP(c.ConfigDir)
	return nil
}

func getIdentitiesFromLegacyCtx(c *config.Config, p *ExtendedProtocol) (identities []*ent.Identity, err error) {
	log.Infof("loading existing identities from file system")

	secret16Bytes, err := base64.StdEncoding.DecodeString(c.Secret16Base64)
	if err != nil {
		return nil, fmt.Errorf("unable to decode secret for legacy key store (%s): %v", c.Secret16Base64, err)
	}
	if len(secret16Bytes) != 16 {
		return nil, fmt.Errorf("invalid secret for legacy key store: secret length must be 16 bytes (is %d)", len(secret16Bytes))
	}

	fileManager, err := NewFileManager(c.ConfigDir, secret16Bytes)
	if err != nil {
		return nil, err
	}

	uids, err := fileManager.EncryptedKeystore.GetIDs()
	if err != nil {
		return nil, err
	}

	if len(uids) == 0 {
		return nil, fmt.Errorf("%s not found or empty", fileManager.KeyFile)
	}

	for _, uid := range uids {

		i := &ent.Identity{
			Uid: uid,
		}

		i.PrivateKey, err = fileManager.GetPrivateKey(uid)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", uid, err)
		}

		i.PublicKey, err = fileManager.GetPublicKey(uid)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", uid, err)
		}

		i.Signature, err = fileManager.GetSignature(uid)
		if err != nil {
			if os.IsNotExist(err) { // if file does not exist, create genesis signature
				i.Signature = make([]byte, p.SignatureLength())
			} else { // file exists but something went wrong
				return nil, fmt.Errorf("%s: %v", uid, err)
			}
		}

		// get auth token from config
		i.AuthToken = c.Devices[uid.String()]

		identities = append(identities, i)
	}

	return identities, nil
}

func migrateIdentities(c *config.Config, p *ExtendedProtocol) error {
	// migrate from file based context
	identities, err := getIdentitiesFromLegacyCtx(c, p)
	if err != nil {
		return err
	}

	log.Infof("starting migration from legacy context files to DB...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := p.StartTransaction(ctx)
	if err != nil {
		return err
	}

	for i, id := range identities {
		log.Infof("%4d: %s", i+1, id.Uid)

		initialized, err := p.IsInitialized(id.Uid)
		if err != nil {
			return err
		}

		if initialized {
			log.Warnf("skipping %s: already initialized", id.Uid)
			continue
		}

		err = p.StoreIdentity(tx, *id)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func cleanUP(configDir string) {
	log.Infof("removing legacy context from file system")

	keyFile := filepath.Join(configDir, keyFileName)
	err := os.Remove(keyFile)
	if err != nil {
		log.Warnf("could not remove key file %s from file system: %v", keyFile, err)
	}

	keyFileBck := filepath.Join(configDir, keyFileName+".bck")
	err = os.Remove(keyFileBck)
	if err != nil && !os.IsNotExist(err) {
		log.Warnf("could not remove key backup file %s from file system: %v", keyFileBck, err)
	}

	signatureDir := filepath.Join(configDir, signatureDirName)
	err = os.RemoveAll(signatureDir)
	if err != nil {
		log.Warnf("could not remove signature directory %s from file system: %v", signatureDir, err)
	}
}
