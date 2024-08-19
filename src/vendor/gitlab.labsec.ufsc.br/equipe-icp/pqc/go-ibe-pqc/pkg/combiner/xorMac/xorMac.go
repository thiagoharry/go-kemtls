package xormac

import (
	//"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	//"errors"
	"gitlab.labsec.ufsc.br/equipe-icp/pqc/go-ibe-pqc/pkg/combiner"
	"gitlab.labsec.ufsc.br/equipe-icp/pqc/go-ibe-pqc/pkg/idkem"
	"gitlab.labsec.ufsc.br/equipe-icp/pqc/go-ibe-pqc/pkg/kem"
)

// KEM struct implements the Hybrid KEM interface.
type KEM struct {
	pki_kem kem.KEM
	id_kem  idkem.KEM
}

// Scheme wraps up the Hybrid KEM methods.
type Scheme struct {
	pki_scheme kem.Scheme
	id_scheme  idkem.Scheme
}

// Combiner implements a method for generating a new Hybrid KEM given a PKI-based KEM and an Identity-Based KEM.
type Combiner struct{}

// Name returns a string with the combiner name.
func (Combiner) Name() string {
	return "XOR-then-MAC"
}

// NewScheme produces a new hybrid scheme mixing a PKI-based KEM and an Identity-Based KEM.
func (Combiner) NewScheme(pki_sc kem.Scheme, id_sc idkem.Scheme) (combiner.HybridScheme, error) {
	ret := new(Scheme)
	ret.pki_scheme = pki_sc
	ret.id_scheme = id_sc
	return ret, nil
}

// Returns a new Hybrid KEM interface, which will have internally a pair composed by the master public key and master secret key
func (sc Scheme) KeyGen(n int) (combiner.HybridKEM, error) {
	var err error
	ret := new(KEM)
	ret.pki_kem, err = sc.pki_scheme.KeyGen(n)
	if err != nil {
		return nil, err
	}
	ret.id_kem, err = sc.id_scheme.KeyGen(n)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// Given a master public key and an user public key, both represented as byte slices, it returns a new Hybrid KEM interface that would be able to encapsulate a secret to the for some user identified by the given public key, provided that it also knows the user identity.
func (sc Scheme) Encapsulator(mpk []byte, pk []byte) (combiner.HybridKEM, error) {
	var err error
	ret := new(KEM)
	ret.pki_kem, err = sc.pki_scheme.Encapsulator(pk)
	if err != nil {
		return nil, err
	}
	ret.id_kem, err = sc.id_scheme.Encapsulator(mpk)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// Given a secret key associated with some identity represented as a byte slice, it generates a new PKI-based secret key and returns a new Hybrid KEM interface, that knows both secret keys.
func (sc Scheme) NewDecapsulator(n int, skID []byte) (combiner.HybridKEM, error) {
	var err error
	ret := new(KEM)
	ret.pki_kem, err = sc.pki_scheme.KeyGen(n)
	if err != nil {
		return nil, err
	}
	ret.id_kem, err = sc.id_scheme.Decapsulator(skID)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// Given a secret key represented as a byte slice and a PKI-based secret key, it returns a new Hybrid KEM interface that would be able to decapsulate secrets encapsulated to the identity associated with both secret keys. This assumes that both keys were already generated in the past and we are just instantiating a new KEM with these known keys.
func (sc Scheme) Decapsulator(sk []byte, skID []byte) (combiner.HybridKEM, error) {
	var err error
	ret := new(KEM)
	ret.pki_kem, err = sc.pki_scheme.Decapsulator(sk)
	if err != nil {
		return nil, err
	}
	ret.id_kem, err = sc.id_scheme.Decapsulator(skID)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// Returns a stirng with the scheme name.
func (sc Scheme) Name() string {
	return "XOR-then_MAC(" + sc.pki_scheme.Name() + "," + sc.id_scheme.Name() + ")"
}

// If this interface has a master secret key, this method produces a new secret key associated with the identity given as parameter. Otherwise, it generates an error.
func (k KEM) Extract(id string) ([]byte, error) {
	return k.id_kem.Extract(id)
}

// Returns the minimun integer, given two values.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Encapsulates a secret to some user given its identity and the PKI public key associated with this interface instance. It produces an error if this interface does not have a PKI public key associated.
func (k KEM) Encaps(id string) ([]byte, []byte, error) {
	var err error
	c1, k1, err := k.pki_kem.Encaps()
	if err != nil {
		return nil, nil, err
	}
	c2, k2, err := k.id_kem.Encaps(id)
	if err != nil {
		return nil, nil, err
	}
	c1_size := make([]byte, 4)
	binary.LittleEndian.PutUint32(c1_size, uint32(len(c1)))
	c1 = append(c1_size, c1...)
	size_sec := min(len(k1), len(k2))
	size_sec = size_sec / 2
	//k_mac := append(k1[size_sec:], k2[size_sec:]...)
	k1a := k1[:size_sec]
	k2a := k2[:size_sec]
	for i := range k1a {
		k1a[i] = k1a[i] ^ k2a[i]
	}
	c := append(c1, c2...)
	//hash := hmac.New(sha256.New, k_mac)
	//hash.Write(c[4:])
	//t := hash.Sum(nil)
	return c, k1a, nil
}

// If this interface instance has a pair of secret keys, a PKI-based key and a identity-based key, this method allows us to decapsulate secrets encapsulated for the it. Otherwise, it produces an error
func (k KEM) Decaps(id string, c []byte) ([]byte, error) {
	var err error
	//t := make([]byte, 32)
	//copy(t, cc[len(cc)-32:])
	//c := cc[:len(cc)-32]
	c1_size := c[:4]
	c = c[4:]
	size := binary.LittleEndian.Uint32(c1_size)
	c1 := c[:size]
	c2 := c[size:]
	k1 := k.pki_kem.Decaps(c1)
	if err != nil {
		return nil, err
	}
	k2, err := k.id_kem.Decaps(id, c2)
	if err != nil {
		return nil, err
	}
	size_sec := min(len(k1), len(k2))
	size_sec = size_sec / 2
	k_mac := append(k1[size_sec:], k2[size_sec:]...)
	k1a := k1[:size_sec]
	k2a := k2[:size_sec]
	hash := hmac.New(sha256.New, k_mac)
	hash.Write(c)
	//t2 := hash.Sum(nil)

	//if bytes.Compare(t2, t) != 0 {
	//	return nil, errors.New("Invalid ciphertext in decaps method.")
	//}
	for i := range k1a {
		k1a[i] = k1a[i] ^ k2a[i]
	}
	return k1a, nil
}

// Exports the master public key as a byte slice.
func (k KEM) MasterPublic() ([]byte, error) {
	return k.id_kem.MasterPublic()
}

// Exports the PKI-based public key as a byte slice. If no PKI-based key is know, returns an error.
func (k KEM) Public() ([]byte, error) {
	return k.pki_kem.Public()
}

// Exports both secret keys (the PKI-based key and the identity-based key) associated with the interface as a byte slice. Returns an error if the instance does not have secret keys.
func (k KEM) Private() ([]byte, []byte, error) {
	pki_sk, err := k.pki_kem.Private()
	if err != nil {
		return nil, nil, err
	}
	id_sk, err := k.id_kem.IDPrivate()
	if err != nil {
		return nil, nil, err
	}
	return pki_sk, id_sk, nil
}

// Deallocate memory reserved to the interface. Run this method after using the interface.
func (k KEM) Close() {
	if k.pki_kem != nil {
		k.pki_kem.Close()
	}
	if k.id_kem != nil {
		k.id_kem.Close()
	}
}
