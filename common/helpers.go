package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"github.com/joho/godotenv"
)
func init() {
    godotenv.Load()
}
// MustEnv returns env value or panics (used at startup)
func MustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic("missing env: " + key)
	}
	return v
}

// MaybeEnv returns environment value or empty string (non-panicking)
func MaybeEnv(key string) string {
    return os.Getenv(key)
}


// DecodeBase64Key decodes a base64-encoded key string
func DecodeBase64Key(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

/*
 AES-GCM encrypt/decrypt helpers.

 AESGCMEncrypt returns a base64-encoded string containing nonce||ciphertext.
 AESGCMDecrypt expects that base64 string and returns plaintext []byte.
*/
func AESGCMEncrypt(aesKey []byte, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	data := append(nonce, ciphertext...)
	return base64.StdEncoding.EncodeToString(data), nil
}

func AESGCMDecrypt(aesKey []byte, encoded string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := aesgcm.NonceSize()
	if len(data) < ns {
		return nil, errors.New("ciphertext too short")
	}
	nonce := data[:ns]
	ciphertext := data[ns:]
	plain, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

// HMACBlindIndex computes HMAC-SHA256 and returns hex string
func HMACBlindIndex(hmacKey []byte, value string) string {
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

/*
 FPT helpers

 - FPTFromBlindIndex (legacy): uses counter==0 primary candidate
 - FPTFromBlindIndexWithCounter: deterministic generator using counter to produce alternate candidates
*/

func FPTFromBlindIndex(blindHex string, original string, dataType string) (string, error) {
	return FPTFromBlindIndexWithCounter(blindHex, original, dataType, 0)
}

// FPTFromBlindIndexWithCounter returns a deterministic format-preserving token derived from blindHex and counter.
// Supported dataType: "PAN" (5 letters + 4 digits + 1 letter), "AADHAR" (numeric, same length as original).
// For other types we fall back to base36 uppercase trimmed/padded to original length.
func FPTFromBlindIndexWithCounter(blindHex, original, dataType string, counter int) (string, error) {
	switch strings.ToUpper(dataType) {
	case "PAN":
		return fptPANFromBlind(blindHex, counter)
	case "AADHAR":
		return fptDigitsFromBlind(blindHex, len(original), counter)
	default:
		return deterministicBase36FromHexWithCounter(blindHex, len(original), counter)
	}
}

func fptPANFromBlind(blindHex string, counter int) (string, error) {
	// PAN format: 5 letters, 4 digits, 1 letter => total 10 chars
	// Use SHA256(blindHex:counter) and map bytes into required ranges
	src := sha256.Sum256([]byte(blindHex + ":" + fmt.Sprint(counter)))
	b := src[:]

	out := make([]byte, 10)
	// 5 letters
	for i := 0; i < 5; i++ {
		out[i] = byte('A' + (b[i] % 26))
	}
	// 4 digits
	for i := 0; i < 4; i++ {
		out[5+i] = byte('0' + (b[5+i] % 10))
	}
	// final letter
	out[9] = byte('A' + (b[9] % 26))
	return string(out), nil
}

func fptDigitsFromBlind(blindHex string, length, counter int) (string, error) {
	if length <= 0 {
		return "", errors.New("invalid length for digits fpt")
	}
	// accumulate enough bytes using repeated hashes
	result := make([]byte, 0, length)
	round := 0
	for len(result) < length {
		src := sha256.Sum256([]byte(blindHex + ":" + fmt.Sprint(counter) + ":" + fmt.Sprint(round)))
		result = append(result, src[:]...)
		round++
	}
	out := make([]byte, length)
	for i := 0; i < length; i++ {
		out[i] = byte('0' + (result[i] % 10))
	}
	return string(out), nil
}

func deterministicBase36FromHexWithCounter(hexstr string, length int, counter int) (string, error) {
	// Use sha256(hexstr + ":" + counter) and convert to base36 uppercase
	src := sha256.Sum256([]byte(hexstr + ":" + fmt.Sprint(counter)))
	bi := new(big.Int).SetBytes(src[:])
	s := strings.ToUpper(bi.Text(36))
	if len(s) < length {
		for len(s) < length {
			h := sha256.Sum256([]byte(s + fmt.Sprint(counter)))
			s += strings.ToUpper(new(big.Int).SetBytes(h[:]).Text(36))
		}
	}
	if len(s) > length {
		s = s[:length]
	}
	return s, nil
}
