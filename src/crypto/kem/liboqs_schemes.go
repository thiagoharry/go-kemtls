package kem

import (
	"circl/hpke"
	"circl/kem"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// Scheme for a Liboqs hybrid KEM.

type liboqsHybridScheme struct {
	pqcName string // Passed as argument to oqs.KeyEncapsulation.Init()
	classic kem.Scheme
	pqc     oqs.KeyEncapsulation
}

/* ---------------------------------- Kyber --------------------------------- */

var p256_kyber512 liboqsHybridScheme = liboqsHybridScheme{
	"Kyber512",
	hpke.KEM_P256_HKDF_SHA256.Scheme(),
	oqs.KeyEncapsulation{},
}

var p384_kyber768 liboqsHybridScheme = liboqsHybridScheme{
	"Kyber768",
	hpke.KEM_P384_HKDF_SHA384.Scheme(),
	oqs.KeyEncapsulation{},
}

var p521_kyber1024 liboqsHybridScheme = liboqsHybridScheme{
	"Kyber1024",
	hpke.KEM_P521_HKDF_SHA512.Scheme(),
	oqs.KeyEncapsulation{},
}

/* ---------------------------------- Saber --------------------------------- */

var p256_lightsaber_kem liboqsHybridScheme = liboqsHybridScheme{
	"LightSaber-KEM",
	hpke.KEM_P256_HKDF_SHA256.Scheme(),
	oqs.KeyEncapsulation{},
}

var p384_saber_kem liboqsHybridScheme = liboqsHybridScheme{
	"Saber-KEM",
	hpke.KEM_P384_HKDF_SHA384.Scheme(),
	oqs.KeyEncapsulation{},
}

var p521_firesaber_kem liboqsHybridScheme = liboqsHybridScheme{
	"FireSaber-KEM",
	hpke.KEM_P521_HKDF_SHA512.Scheme(),
	oqs.KeyEncapsulation{},
}

/* ---------------------------------- NTRU ---------------------------------- */

var p256_ntru_hps_2048_509 liboqsHybridScheme = liboqsHybridScheme{
	"NTRU-HPS-2048-509",
	hpke.KEM_P256_HKDF_SHA256.Scheme(),
	oqs.KeyEncapsulation{},
}

var p384_ntru_hps_2048_677 liboqsHybridScheme = liboqsHybridScheme{
	"NTRU-HPS-2048-677",
	hpke.KEM_P384_HKDF_SHA384.Scheme(),
	oqs.KeyEncapsulation{},
}

var p521_ntru_hps_4096_821 liboqsHybridScheme = liboqsHybridScheme{
	"NTRU-HPS-4096-821",
	hpke.KEM_P521_HKDF_SHA512.Scheme(),
	oqs.KeyEncapsulation{},
}

var p521_ntru_hps_4096_1229 liboqsHybridScheme = liboqsHybridScheme{
	"NTRU-HPS-4096-1229",
	hpke.KEM_P521_HKDF_SHA512.Scheme(),
	oqs.KeyEncapsulation{},
}

var p384_ntru_hrss_701 liboqsHybridScheme = liboqsHybridScheme{
	"NTRU-HRSS-701",
	hpke.KEM_P384_HKDF_SHA384.Scheme(),
	oqs.KeyEncapsulation{},
}

var p521_ntru_hrss_1373 liboqsHybridScheme = liboqsHybridScheme{
	"NTRU-HRSS-1373",
	hpke.KEM_P521_HKDF_SHA512.Scheme(),
	oqs.KeyEncapsulation{},
}

var p256_classic_mceliece_348864 liboqsHybridScheme = liboqsHybridScheme{
	"Classic-McEliece-348864",
	hpke.KEM_P256_HKDF_SHA256.Scheme(),
	oqs.KeyEncapsulation{},
}

/* ------------------------------------ . ----------------------------------- */

var liboqsSchemeMap = map[ID]liboqsHybridScheme{P256_Kyber512: p256_kyber512, P384_Kyber768: p384_kyber768, P521_Kyber1024: p521_kyber1024,
	P256_LightSaber_KEM: p256_lightsaber_kem, P384_Saber_KEM: p384_saber_kem, P521_FireSaber_KEM: p521_firesaber_kem,
	P256_NTRU_HPS_2048_509: p256_ntru_hps_2048_509, P384_NTRU_HPS_2048_677: p384_ntru_hps_2048_677, P521_NTRU_HPS_4096_821: p521_ntru_hps_4096_821, P521_NTRU_HPS_4096_1229: p521_ntru_hps_4096_1229,
	P384_NTRU_HRSS_701: p384_ntru_hrss_701, P521_NTRU_HRSS_1373: p521_ntru_hrss_1373, P256_Classic_McEliece_348864: p256_classic_mceliece_348864}

var liboqsPQCKEMString = map[ID]string {
		OQS_Kyber512: "Kyber512", OQS_Kyber768: "Kyber768", OQS_Kyber1024: "Kyber1024",
		LightSaber_KEM: "LightSaber-KEM", Saber_KEM: "Saber-KEM", FireSaber_KEM: "FireSaber-KEM", 
		NTRU_HPS_2048_509: "NTRU-HPS-2048-509", NTRU_HPS_2048_677: "NTRU-HPS-2048-677", NTRU_HPS_4096_821: "NTRU-HPS-4096-821",
		NTRU_HPS_4096_1229: "NTRU-HPS-4096-1229", NTRU_HRSS_701: "NTRU-HRSS-701", NTRU_HRSS_1373: "NTRU-HRSS-1373",
}