package encutils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"log"
	"io"
)

const RealmName = "@KERBEROS"

func DeriveSecretKey(password string, salt string) []byte {
	saltedPass := []byte(RealmName+password+salt)
	h := sha256.New()
	_, err := h.Write(saltedPass)
	if err != nil {
		log.Println(err)
		return nil
	}
	return h.Sum(nil)
}


func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}


func Encrypt(key []byte, data any) ([]byte, error) {
	byteData, err := json.Marshal(data)
    if err != nil {
        log.Println("Failed to marshal data", err)
		return nil, err
    }

	c, err := aes.NewCipher(key)
    if err != nil {
        log.Println("Failed to create cipher")
		return nil, err
    }

	gcm, err := cipher.NewGCM(c)
	if err != nil {
        log.Println("Failed to create GCM cipher")
		return nil, err
    }

	nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        log.Println("Failed to create nonce")
		return nil, err
    }

	return gcm.Seal(nonce, nonce, byteData, nil), nil
}


func Decrypt(key []byte, ciphertext []byte, p any) error {
    c, err := aes.NewCipher(key)
    if err != nil {
        log.Println("Failed to create cipher")
		return err
    }

    gcm, err := cipher.NewGCM(c)
    if err != nil {
        log.Println("Failed to create GCM cipher")
		return err
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        log.Println("Invalid ciphertext")
		return err
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    data, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        log.Println("Failed to decode data")
		return err
    }

	err = json.Unmarshal(data, p)
	if err != nil {
        log.Println("Failed to unmarshal data")
		return err
    }
	return nil
}