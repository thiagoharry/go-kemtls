package combiner

import (
	"gitlab.labsec.ufsc.br/equipe-icp/pqc/go-ibe-pqc/pkg/idkem"
	"gitlab.labsec.ufsc.br/equipe-icp/pqc/go-ibe-pqc/pkg/kem"
)

// HybridKEM is the interface that wraps the basic KEM methods.
type HybridKEM interface {
	Extract(id string) ([]byte, error)
	Encaps(id string) ([]byte, []byte, error)
	Decaps(id string, c []byte) ([]byte, error)
	MasterPublic() ([]byte, error)
	Public() ([]byte, error)
	Private() ([]byte, []byte, error)
	Close()
}

// HybridScheme is the interface that wraps the basic Hybrid KEM methods.
type HybridScheme interface {
	KeyGen(n int) (HybridKEM, error)
	Encapsulator(mpk []byte, pk []byte) (HybridKEM, error)
	NewDecapsulator(n int, skID []byte) (HybridKEM, error)
	Decapsulator(sk []byte, skID []byte) (HybridKEM, error)
	Name() string
}

// Combiner is the interface that wraps the basic NewScheme method.
type Combiner interface {
	Name() string
	NewScheme(kem.Scheme, idkem.Scheme) (HybridScheme, error)
}
