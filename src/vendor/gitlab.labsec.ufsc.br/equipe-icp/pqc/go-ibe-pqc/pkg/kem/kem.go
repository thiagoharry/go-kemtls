// Package kem defines Key Exchange Mechanisms (KEMs)
package kem

// KEM is the interface that defines the KEM scheme.
type KEM interface {
	Encaps() ([]byte, []byte, error)
	Decaps(c []byte) []byte
	Public() ([]byte, error)
	Private() ([]byte, error)
	Close()
}

// Scheme is the interface that defines the KEM scheme.
type Scheme interface {
	KeyGen(n int) (KEM, error)
	Encapsulator(pk []byte) (KEM, error)
	Decapsulator(sk []byte) (KEM, error)
	Name() string
}
