// Package ec implements the KEM interface for the elliptic curve scheme.
package ec

import (
	"errors"

	"github.com/cloudflare/circl/hpke"
	circlkem "github.com/cloudflare/circl/kem"
	"gitlab.labsec.ufsc.br/equipe-icp/pqc/go-ibe-pqc/pkg/kem"
)

// ECKem implements the KEM interface for the elliptic curve scheme.
type Eckem struct {
	PrivateKey circlkem.PrivateKey
	PublicKey  circlkem.PublicKey
}

// Scheme implements the KEM interface.
type Scheme struct{}

// KeyGen generates a new key pair for the elliptic curve KEM scheme.
func (ec Scheme) KeyGen(n int) (kem.KEM, error) {
	var ret = new(Eckem)
	if n == 128 {
		scheme := hpke.KEM_P256_HKDF_SHA256.Scheme()
		ret.PublicKey, ret.PrivateKey, _ = scheme.GenerateKeyPair()
	} else if n == 192 {
		scheme := hpke.KEM_P384_HKDF_SHA384.Scheme()
		ret.PublicKey, ret.PrivateKey, _ = scheme.GenerateKeyPair()
	} else {
		return nil, errors.New("this implementation supports only 128 amd 192 bits of security")
	}
	return ret, nil
}

// Encapsulator is the function that returns a new elliptic curve KEM instance for encapsulation.
func (rs Scheme) Encapsulator(pk []byte) (kem.KEM, error) {
	var err error
	var ret = new(Eckem)
	scheme := hpke.KEM_P256_HKDF_SHA256.Scheme()
	ret.PrivateKey = nil
	ret.PublicKey, err = scheme.UnmarshalBinaryPublicKey(pk)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// Name is the function that returns the name of the elliptic curve KEM scheme.
func (Scheme) Name() string { return "Curve P256 KEM" }

// Encaps encapsulate the public key and returns the ciphertext and the shared secret.
func (ec Eckem) Encaps() ([]byte, []byte, error) {
	scheme := hpke.KEM_P256_HKDF_SHA256.Scheme()

	ct, ss, err := scheme.Encapsulate(ec.PublicKey)

	if err != nil {
		return nil, nil, err
	}

	return ct, ss, nil
}

// Decaps decapsulate the ciphertext and returns the shared secret.
func (ec Eckem) Decaps(ct []byte) []byte {
	scheme := hpke.KEM_P256_HKDF_SHA256.Scheme()

	by, err := scheme.Decapsulate(ec.PrivateKey, ct)

	if err != nil {
		return nil
	}

	return by
}

// Close is the function that closes the elliptic curve KEM instance.
func (rs Eckem) Close() {
}

// Public is the function that returns the public key.
func (rs Eckem) Public() ([]byte, error) {
	return rs.PublicKey.MarshalBinary()
}

// Private is the function that returns the private key.
func (rs Eckem) Private() ([]byte, error) {
	return rs.PrivateKey.MarshalBinary()
}

// Decapsulator is the function that returns a new elliptic curve KEM instance for decapsulation.
func (rs Scheme) Decapsulator(sk []byte) (kem.KEM, error) {
	var err error
	var ret = new(Eckem)

	scheme := hpke.KEM_P256_HKDF_SHA256.Scheme()
	ret.PrivateKey, err = scheme.UnmarshalBinaryPrivateKey(sk)
	if err != nil {
		return nil, err
	}
	ret.PublicKey = ret.PrivateKey.Public()
	return ret, nil
}
