package password_hashing

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"runtime"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/argon2"
	"golang.org/x/sync/semaphore"

	prom "github.com/ubirch/ubirch-client-go/main/prometheus"
)

const (
	KeyLen            = 24
	SaltLen           = 16
	stdEncodingFormat = "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"
)

type Argon2idKeyDerivator struct {
	sem *semaphore.Weighted
}

func NewArgon2idKeyDerivator(maxTotalMemMiB uint32) *Argon2idKeyDerivator {
	return &Argon2idKeyDerivator{
		sem: semaphore.NewWeighted(int64(maxTotalMemMiB) * 1024),
	}
}

type Argon2idParams struct {
	Memory  uint32 // the memory parameter specifies the size of the memory in KiB
	Time    uint32 // the time parameter specifies the number of passes over the memory
	Threads uint8  // the threads parameter specifies the number of threads and can be adjusted to the numbers of available CPUs
	KeyLen  uint32 // the length of the resulting derived key in byte
	SaltLen uint32 // the length of the random salt in byte
}

func GetArgon2idParams(mem, time uint32, threads uint8) *Argon2idParams {
	return &Argon2idParams{
		Memory:  mem,
		Time:    time,
		Threads: threads,
		KeyLen:  KeyLen,
		SaltLen: SaltLen,
	}
}

func (kd *Argon2idKeyDerivator) DefaultParams() *Argon2idParams {
	mem := uint32(15 * 1024) // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
	time := uint32(2)
	threads := uint8(runtime.NumCPU()) // number of cores

	return GetArgon2idParams(mem, time, threads)
}

// GeneratePasswordHash derives a key from the password, salt, and cost parameters using Argon2id
// returning the standard encoded representation of the hashed password
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-argon2-03
func (kd *Argon2idKeyDerivator) GeneratePasswordHash(ctx context.Context, pw string, params *Argon2idParams) (string, error) {
	salt := make([]byte, params.SaltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	if kd.sem != nil {
		err = kd.sem.Acquire(ctx, int64(params.Memory))
		if err != nil {
			return "", fmt.Errorf("failed to acquire semaphore for key derivation: %v", err)
		}
		defer kd.sem.Release(int64(params.Memory))
	}

	hash := argon2.IDKey([]byte(pw), salt, params.Time, params.Memory, params.Threads, params.KeyLen)

	return encodePasswordHash(params, salt, hash), nil
}

func (kd *Argon2idKeyDerivator) CheckPassword(ctx context.Context, pwToCheck string, pwHash string) (bool, error) {
	p, salt, hash, err := decodePasswordHash(pwHash)
	if err != nil {
		return false, fmt.Errorf("failed to decode argon2id password hash: %v", err)
	}

	if kd.sem != nil {
		timerWait := prometheus.NewTimer(prom.AuthCheckWithWaitDuration)
		defer timerWait.ObserveDuration()
		err = kd.sem.Acquire(ctx, int64(p.Memory))
		if err != nil {
			return false, fmt.Errorf("failed to acquire semaphore for key derivation: %v", err)
		}
		defer kd.sem.Release(int64(p.Memory))
	}

	timerAuth := prometheus.NewTimer(prom.AuthCheckDuration)
	defer timerAuth.ObserveDuration()
	hashToCheck := argon2.IDKey([]byte(pwToCheck), salt, p.Time, p.Memory, p.Threads, p.KeyLen)

	return bytes.Equal(hash, hashToCheck), nil
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
