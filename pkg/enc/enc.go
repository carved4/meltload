package enc


import (
	"fmt"
	"crypto/rand"
	"time"

	"github.com/carved4/go-wincall"
)

type UString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *byte 
}

func EncryptDecryptBuffer(buffer *[]byte, key []byte, sleepSeconds int) {
	var dataUString UString
	var keyUString UString
	dataUString.Buffer = &(*buffer)[0]
	dataUString.Length = uint16(len(*buffer))
	dataUString.MaximumLength = uint16(len(*buffer))
	keyUString.Buffer = &key[0]
	keyUString.Length = uint16(len(key))
	keyUString.MaximumLength = uint16(len(key))
	
	wincall.Call("SystemFunction032", "advapi32.dll", &dataUString, &keyUString)
	
	if sleepSeconds > 0 {
		time.Sleep(time.Duration(sleepSeconds) * time.Second)
	}
	
	wincall.Call("SystemFunction032", "advapi32.dll", &dataUString, &keyUString)
}
// used in contexts like encrypting the mapped dll before melt and after its own execution
func EncryptBuffer(buffer *[]byte, key []byte) {
	var dataUString UString
	var keyUString UString
	dataUString.Buffer = &(*buffer)[0]
	dataUString.Length = uint16(len(*buffer))
	dataUString.MaximumLength = uint16(len(*buffer))
	keyUString.Buffer = &key[0]
	keyUString.Length = uint16(len(key))
	keyUString.MaximumLength = uint16(len(key))
	wincall.Call("SystemFunction032", "advapi32.dll", &dataUString, &keyUString)
}

// optional, this is purely for naming conventions, you could very well call encryptbuffer() again and achieve the same affect
// rc4 is symmetric
func DecryptBuffer(buffer *[]byte, key []byte) {
	var dataUString UString
	var keyUString UString
	dataUString.Buffer = &(*buffer)[0]
	dataUString.Length = uint16(len(*buffer))
	dataUString.MaximumLength = uint16(len(*buffer))
	keyUString.Buffer = &key[0]
	keyUString.Length = uint16(len(key))
	keyUString.MaximumLength = uint16(len(key))
	wincall.Call("SystemFunction032", "advapi32.dll", &dataUString, &keyUString)
}

// used to generate key for rc4, use 16 or 32 as size param
func GenerateKey(keySize int) ([]byte, error) {
	key := make([]byte, keySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	return key, nil
}

// used to wipe key from memory, not necessary very optional
func SecureWipeBuffer(buffer *[]byte) {
	if buffer == nil || len(*buffer) == 0 {
		return
	}
	
	for pass := 0; pass < 3; pass++ {
		switch pass {
		case 0:
			rand.Read(*buffer)
		case 1:
			for i := range *buffer {
				(*buffer)[i] = 0x00
			}
		case 2:
			for i := range *buffer {
				(*buffer)[i] = 0xFF
			}
		}
	}
	
	rand.Read(*buffer)
}
