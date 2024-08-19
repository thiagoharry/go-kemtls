// Package idkem defines Identity-Based Key Exchange Mechanisms (KEMs)
package idkem

// KEM is the interface that wraps the basic IDKEM methods.
type KEM interface {
	Extract(id string) ([]byte, error)
	Encaps(id string) ([]byte, []byte, error)
	Decaps(id string, c []byte) ([]byte, error)
	MasterPublic() ([]byte, error)
	IDPrivate() ([]byte, error)
	Close()
}

// Scheme is the interface that wraps the basic IDKEM Encryption methods.
type Scheme interface {
	KeyGen(n int) (KEM, error)
	Encapsulator(mpk []byte) (KEM, error)
	Decapsulator(skID []byte) (KEM, error)
	Name() string
}
