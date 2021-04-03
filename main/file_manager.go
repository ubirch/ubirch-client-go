package main

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

const (
	keyFileName       = "keys.json"
	SignatureFileName = "signatures.json"
)

type FileManager struct {
	keyFile       string
	signatureFile string
}

// Ensure FileManager implements the ContextManager interface
var _ ContextManager = (*FileManager)(nil)

func NewFileManager(contextDir string) *FileManager {
	return &FileManager{
		keyFile:       filepath.Join(contextDir, keyFileName),
		signatureFile: filepath.Join(contextDir, SignatureFileName),
	}
}

func (f *FileManager) LoadKeys(dest interface{}) error {
	return loadFile(f.keyFile, dest)
}

func (f *FileManager) PersistKeys(source interface{}) error {
	return persistFile(f.keyFile, source)
}

func (f *FileManager) LoadSignatures(dest interface{}) error {
	return loadFile(f.signatureFile, dest)
}

func (f *FileManager) PersistSignatures(source interface{}) error {
	return persistFile(f.signatureFile, source)
}

func (f *FileManager) Close() error {
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
	return ioutil.WriteFile(file, contextBytes, 444)
}
