package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemory      uint32 = 64 * 1024
	argonIterations  uint32 = 3
	argonParallelism uint8  = 4
	argonSaltLength         = 16
	argonKeyLength          = 32
)

var ErrInvalidHash = errors.New("invalid password hash")

func HashPassword(password string) (string, error) {
	if strings.TrimSpace(password) == "" {
		return "", errors.New("password is required")
	}

	salt := make([]byte, argonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLength)
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedKey := base64.RawStdEncoding.EncodeToString(key)

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonIterations, argonParallelism, encodedSalt, encodedKey), nil
}

func VerifyPassword(password string, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false, ErrInvalidHash
	}

	params, err := parseParams(parts[3])
	if err != nil {
		return false, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}

	key := argon2.IDKey([]byte(password), salt, params.time, params.memory, params.threads, uint32(len(expected)))
	if subtle.ConstantTimeCompare(key, expected) != 1 {
		return false, nil
	}
	return true, nil
}

type argonParams struct {
	memory  uint32
	time    uint32
	threads uint8
}

func parseParams(value string) (argonParams, error) {
	out := argonParams{}
	for _, part := range strings.Split(value, ",") {
		keyValue := strings.SplitN(part, "=", 2)
		if len(keyValue) != 2 {
			return out, ErrInvalidHash
		}
		parsed, err := strconv.ParseUint(keyValue[1], 10, 32)
		if err != nil {
			return out, err
		}
		switch keyValue[0] {
		case "m":
			out.memory = uint32(parsed)
		case "t":
			out.time = uint32(parsed)
		case "p":
			if parsed > 255 {
				return out, ErrInvalidHash
			}
			out.threads = uint8(parsed)
		default:
			return out, ErrInvalidHash
		}
	}
	if out.memory == 0 || out.time == 0 || out.threads == 0 {
		return out, ErrInvalidHash
	}
	return out, nil
}
