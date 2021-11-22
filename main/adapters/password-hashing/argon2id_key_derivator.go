package password_hashing

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/argon2"
	"golang.org/x/sync/semaphore"

	prom "github.com/ubirch/ubirch-client-go/main/prometheus"
)

const (
	DefaultMemory      uint32 = 15
	DefaultTime        uint32 = 2
	DefaultParallelism uint8  = 1
	DefaultKeyLen      uint32 = 32
	DefaultSaltLen     uint32 = 16
	stdEncodingFormat         = "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"
)

type Argon2idKeyDerivator struct {
	sem          *semaphore.Weighted
	Params       *Argon2idParams
	updateParams bool
}

func NewArgon2idKeyDerivator(maxTotalMemMiB uint32, params *Argon2idParams, updateParams bool) *Argon2idKeyDerivator {
	var s *semaphore.Weighted = nil

	if maxTotalMemMiB != 0 {
		s = semaphore.NewWeighted(int64(maxTotalMemMiB) * 1024)
	}

	return &Argon2idKeyDerivator{
		sem:          s,
		Params:       params,
		updateParams: updateParams,
	}
}

type Argon2idParams struct {
	Memory  uint32 // the memory parameter specifies the size of the memory in KiB
	Time    uint32 // the time parameter specifies the number of passes over the memory
	Threads uint8  // the threads parameter specifies the number of threads and can be adjusted to the numbers of available CPUs
	KeyLen  uint32 // the length of the resulting derived key in byte
	SaltLen uint32 // the length of the random salt in byte
}

func GetArgon2idParams(memMiB, time uint32, threads uint8, keyLen, saltLen uint32) *Argon2idParams {
	if memMiB == 0 {
		memMiB = DefaultMemory
	}

	if time == 0 {
		time = DefaultTime
	}

	if threads == 0 {
		threads = DefaultParallelism
	}

	if keyLen == 0 {
		keyLen = DefaultKeyLen
	}

	if saltLen == 0 {
		saltLen = DefaultSaltLen
	}

	return &Argon2idParams{
		Memory:  memMiB * 1024,
		Time:    time,
		Threads: threads,
		KeyLen:  keyLen,
		SaltLen: saltLen,
	}
}

func GetDefaultArgon2idParams() *Argon2idParams {
	// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
	return GetArgon2idParams(DefaultMemory, DefaultTime, DefaultParallelism, DefaultKeyLen, DefaultSaltLen)
}

// GeneratePasswordHash derives a key from the password, salt, and cost parameters using Argon2id
// returning the standard encoded representation of the hashed password
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-argon2-03
func (kd *Argon2idKeyDerivator) GeneratePasswordHash(ctx context.Context, pw string) (string, error) {
	if kd.Params == nil {
		return "", fmt.Errorf("Argon2idParams for key derivation not set")
	}

	salt := make([]byte, kd.Params.SaltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	if kd.sem != nil {
		err = kd.sem.Acquire(ctx, int64(kd.Params.Memory))
		if err != nil {
			return "", fmt.Errorf("failed to acquire semaphore for key derivation: %v", err)
		}
		defer kd.sem.Release(int64(kd.Params.Memory))
	}

	hash := argon2.IDKey([]byte(pw), salt, kd.Params.Time, kd.Params.Memory, kd.Params.Threads, kd.Params.KeyLen)

	return encodePasswordHash(kd.Params, salt, hash), nil
}

func (kd *Argon2idKeyDerivator) CheckPassword(ctx context.Context, pwHash, pwToCheck string) (needsUpdate, ok bool, err error) {
	p, salt, hash, err := decodePasswordHash(pwHash)
	if err != nil {
		return false, false, fmt.Errorf("failed to decode argon2id password hash: %v", err)
	}

	if kd.sem != nil {
		timerWait := prometheus.NewTimer(prom.AuthCheckWithWaitDuration)
		defer timerWait.ObserveDuration()
		err = kd.sem.Acquire(ctx, int64(p.Memory))
		if err != nil {
			return false, false, fmt.Errorf("failed to acquire semaphore for key derivation: %v", err)
		}
		defer kd.sem.Release(int64(p.Memory))
	}

	timerAuth := prometheus.NewTimer(prom.AuthCheckDuration)
	defer timerAuth.ObserveDuration()
	hashToCheck := argon2.IDKey([]byte(pwToCheck), salt, p.Time, p.Memory, p.Threads, p.KeyLen)

	if !bytes.Equal(hash, hashToCheck) {
		return false, false, nil
	}

	if kd.updateParams {
		if *p != *kd.Params {
			return true, true, nil
		}
	}

	return false, true, nil
}

func encodePasswordHash(params *Argon2idParams, salt, hash []byte) string {
	saltBase64 := base64.RawStdEncoding.EncodeToString(salt)
	hashBase64 := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf(stdEncodingFormat, argon2.Version, params.Memory, params.Time, params.Threads, saltBase64, hashBase64)
}

func decodePasswordHash(encodedPasswordHash string) (params *Argon2idParams, salt, hash []byte, err error) {
	vals := strings.Split(encodedPasswordHash, "$")
	if len(vals) != 6 {
		return nil, nil, nil, fmt.Errorf("invalid encoded argon2id password hash: %s", encodedPasswordHash)
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, fmt.Errorf("unsupported argon2id version: %d", version)
	}

	params = &Argon2idParams{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Time, &params.Threads)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}
	params.SaltLen = uint32(len(salt))

	hash, err = base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}
	params.KeyLen = uint32(len(hash))

	return params, salt, hash, nil
}
