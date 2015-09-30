// +build gofuzz

package session

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
)

var key SecretKey

func init() {
	key = make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		log.Fatal(err)
	}
}

func Fuzz(data []byte) int {
	signature := key.sign(data)
	cookieValue := hex.EncodeToString(signature) + hex.EncodeToString(data)

	if _, err := readCookie(cookieValue, key); err != nil {
		return 0
	}

	return 1
}
