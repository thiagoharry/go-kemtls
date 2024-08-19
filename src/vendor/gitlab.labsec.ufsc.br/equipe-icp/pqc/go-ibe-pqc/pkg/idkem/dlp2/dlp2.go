// Package dlp2 implements second DLP-IBE scheme.
package dlp2

//#include "dlp.h"
//#include <stdlib.h>
//#cgo CFLAGS: -O2 -Wall
import "C"

import (
	"crypto/rand"
	"gitlab.labsec.ufsc.br/equipe-icp/pqc/go-ibe-pqc/pkg/idkem"
	"unsafe"
)

// IBE is the struct that wraps the IBE methods.
type KEM struct {
	//sc  *C.dlp
	//rnd []byte
}

// Scheme is the struct that implements encryption methods.
type Scheme struct{}

// Keygen generates a new key pair for the IBE scheme.
func (s Scheme) KeyGen(n int) (idkem.KEM, error) {
	return new(KEM), nil
}

// Given a secret key represented as a byte slice, it returns a new
// IBE interface that would be able to decrypt messages encrypted to
// the identity associated with the given secret key.
func (s Scheme) Decapsulator(skID []byte) (idkem.KEM, error) {
	var ret = new(KEM)
	return ret, nil
}

// Given a master public key represented as a byte slice, it returns a
// new IBE interface that would be able to encrypt messages for any
// identity using that master public key.
func (s Scheme) Encapsulator(mpk []byte) (idkem.KEM, error) {
	var ret = new(KEM)
	return ret, nil
}

// Name returns the name of the IBE scheme.
func (s Scheme) Name() string {
	return "DLP-IBE"
}

// Deallocate memory reserved to the interface. Run this method after
// using the interface.
func (kem KEM) Close() {
}

// Encrypts a plaintext string to the user associated with the given
// identity.
func (kem KEM) Encaps(id string) ([]byte, []byte, error) {
	key := make([]byte, 32)
	ct := make([]byte, 4000)
	idPtr := C.CString(id)
	defer C.free(unsafe.Pointer(idPtr))
	keyPtr := unsafe.Pointer(&key[0])
	ctPtr := unsafe.Pointer(&ct[0])
	C.encrypt(idPtr, keyPtr, ctPtr)
	return ct, key, nil
}

// If this interface instance has a secret key associated with some
// identity, this method allows us to decrypt messages produced for
// that identity. Otherwise, it produces an error.
func (kem KEM) Decaps(id string, cipher []byte) ([]byte, error) {
	key := make([]byte, 32)
	idPtr := C.CString(id)
	defer C.free(unsafe.Pointer(idPtr))
	keyPtr := unsafe.Pointer(&key[0])
	ctPtr := unsafe.Pointer(&cipher[0])
	C.decrypt(idPtr, nil, ctPtr, keyPtr)
	return key, nil
}

func (kem KEM) MasterPublic() ([]byte, error) {
	key := make([]byte, 3584)
	keyPtr := unsafe.Pointer(&key[0])
	C.masterpublic(keyPtr)
	return key, nil
}

func (kem KEM) IDPrivate() ([]byte, error) {
	return nil, nil
}

// If this interface has a master secret key, this method produces a
// new secret key associated with the identity given as
// parameter. Otherwise, it generates an error.
func (kem KEM) Extract(id string) ([]byte, error) {
	key := make([]byte, 4)
	rand.Read(key)
	return key, nil
}
