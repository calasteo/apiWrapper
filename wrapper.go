package apiWrapper

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

type apiWrapper struct {
	Expired   float64
	ClientID  string
	SecretKey string
}
type ApiWrapper interface {
	Encrypt(json string) string
}

func New(Expired float64, ClientID, SecretKey string) ApiWrapper {
	return apiWrapper{
		Expired:   Expired,
		ClientID:  ClientID,
		SecretKey: SecretKey,
	}
}
func (a apiWrapper) Encrypt(json string) string {
	return a.doubleEncrypt(a.reverse(fmt.Sprintf("%v", time.Now().Unix())) + "." + json)
}

func (a apiWrapper) Decrypt(encrypted string) (string, error) {
	parsedString := a.doubleDecrypt(encrypted)
	var lst = strings.SplitN(parsedString, ".", 2)
	if len(lst) < 2 {
		return "", errors.New("parsing error, wrong client_id or secret key or invalid data")
	}
	if a.tsDiff(a.reverse(lst[0])) == false {
		return "", errors.New("payload data has been expired")
	}
	return lst[1], nil
}

func (a apiWrapper) encrypt(payloadInByte []byte, identifier string) []byte {
	var result []byte
	payloadInByteLength := len(payloadInByte)
	identifierLength := len(identifier)
	for i := 0; i < payloadInByteLength; i++ {
		char := payloadInByte[i]
		keyChar := identifier[(i+identifierLength-1)%identifierLength]
		char = byte((int(char) + int(keyChar)) % 128)
		result = append(result, char)
	}
	return result
}

func (a apiWrapper) doubleEncrypt(payload string) string {
	arr := []byte(payload)
	result := a.encrypt(arr, a.ClientID)
	result = a.encrypt(result, a.SecretKey)
	return strings.Replace(strings.Replace(strings.TrimRight(base64.StdEncoding.EncodeToString(result), "="), "+", "-", -1), "/", "_", -1)
}

func (a apiWrapper) reverse(s string) string {
	chars := []rune(s)
	for i, j := 0, len(chars)-1; i < j; i, j = i+1, j-1 {
		chars[i], chars[j] = chars[j], chars[i]
	}
	return string(chars)
}

func (a apiWrapper) doubleDecrypt(str string) string {
	if i := len(str) % 4; i != 0 {
		str += strings.Repeat("=", 4-i)
	}
	result, err := base64.StdEncoding.DecodeString(strings.Replace(strings.Replace(str, "-", "+", -1), "_", "/", -1))
	if err != nil {
		return ""
	}
	result = a.decrypt(result, a.ClientID)
	result = a.decrypt(result, a.SecretKey)
	return string(result[:])
}

func (a apiWrapper) decrypt(payloadInByte []byte, identifier string) []byte {
	var result []byte
	payloadInByteLength := len(payloadInByte)
	identifierLength := len(identifier)
	for i := 0; i < payloadInByteLength; i++ {
		char := payloadInByte[i]
		keyChar := identifier[(i+identifierLength-1)%identifierLength]
		char = byte(((int(char) - int(keyChar)) + 256) % 128)
		result = append(result, char)
	}
	return result
}

func (a apiWrapper) tsDiff(ts string) bool {
	_ts, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	return math.Abs(float64(_ts-time.Now().Unix())) <= a.Expired
}
