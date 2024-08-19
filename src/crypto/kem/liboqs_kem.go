package kem

func IsLiboqs(kemID ID) ID {
	if kemID >= P256_Kyber512 && kemID <= NTRU_HRSS_1373 {
		return kemID
	}
	return 0
}

func isPQCLiboqs(kemID ID) bool {
	if kemID >= OQS_Kyber512 && kemID <= NTRU_HRSS_1373 {
		return true
	}
	return false
}

func (sch *liboqsHybridScheme) Keygen() ([]byte, []byte, error) {

	// Classic
	kemPk1, kemSk1, err := sch.classic.GenerateKeyPair() // using kem.Scheme interface from circl/kem/kem.go
	if err != nil {
		return nil, nil, err
	}

	pk1, err := kemPk1.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	sk1, err := kemSk1.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	// PQC

	// defer keyEncaps.Clean()  // When uncommented, the shared secrets do not match

	if err := sch.pqc.Init(sch.pqcName, nil); err != nil {
		return nil, nil, err
	}

	pk2, err := sch.pqc.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	sk2 := sch.pqc.ExportSecretKey()

	return append(pk1, pk2...), append(sk1, sk2...), nil
}

func (sch *liboqsHybridScheme) Encapsulate(pk *PublicKey) ([]byte, []byte, error) {

	if err := sch.pqc.Init(sch.pqcName, nil); err != nil {
		return nil, nil, err
	}

	classicPk := pk.PublicKey[0:sch.classic.PublicKeySize()]
	pqcPk := pk.PublicKey[sch.classic.PublicKeySize():]

	// Classic
	pk1, err := sch.classic.UnmarshalBinaryPublicKey(classicPk)
	if err != nil {
		return nil, nil, err
	}

	ct1, ss1, err := sch.classic.Encapsulate(pk1)
	if err != nil {
		return nil, nil, err
	}

	// PQC

	ct2, ss2, err := sch.pqc.EncapSecret(pqcPk)
	if err != nil {
		return nil, nil, err
	}

	return append(ct1, ct2...), append(ss1, ss2...), nil
}

func (sch *liboqsHybridScheme) Decapsulate(sk *PrivateKey, ct []byte) ([]byte, error) {

	classicSk := sk.PrivateKey[0:sch.classic.PrivateKeySize()]
	pqcSk := sk.PrivateKey[sch.classic.PrivateKeySize():]

	classicCt := ct[0:sch.classic.CiphertextSize()]
	pqcCt := ct[sch.classic.CiphertextSize():]

	sk1, err := sch.classic.UnmarshalBinaryPrivateKey(classicSk)
	if err != nil {
		return nil, err
	}

	classicSS, err := sch.classic.Decapsulate(sk1, classicCt)
	if err != nil {
		return nil, err
	}

	if err := sch.pqc.Init(sch.pqcName, pqcSk); err != nil {
		return nil, err
	}

	pqcSS, err := sch.pqc.DecapSecret(pqcCt)
	if err != nil {
		return nil, err
	}

	return append(classicSS, pqcSS...), nil
}
