// Copyright 2020-2021 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"
)

// These test keys were generated with the following program, available in the
// crypto/tls directory:
//
//	go run generate_cert.go -ecdsa-curve P256 -host 127.0.0.1 -allowDC
var delegatorCertPEMP256 = `-----BEGIN CERTIFICATE-----
MIIBejCCAR+gAwIBAgIQKEg6iMq02QUu7QZSZJ/qjzAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTIxMDIyNzAwMTYwMVoXDTIyMDIyNzAwMTYwMVow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJTe
bU0Yny6aMvae3zlNj135l7XSzqPDZjYh1PqIqY/P2N5PPmD06fHQ2D7xZRUw/a5z
W7KMwRVXrvur+TVn4+GjVzBVMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggr
BgEFBQcDATAMBgNVHRMBAf8EAjAAMA8GCSsGAQQBgtpLLAQCBQAwDwYDVR0RBAgw
BocEfwAAATAKBggqhkjOPQQDAgNJADBGAiEAvkorBgZm6GidD0Z7tcAJWRq+2YOQ
GVclN1Z1CDljQIoCIQDUlTAqDyRpNJ9ntCHEdOQYe1LfAkJHasok5yCRHC1o8w==
-----END CERTIFICATE-----
`

var delegatorKeyPEMP256 = `-----BEGIN EC PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg4OgO7q8sUUZaYjEp
JuLzlXH0qmTZ1k3UHgPYbAmRFOWhRANCAASU3m1NGJ8umjL2nt85TY9d+Ze10s6j
w2Y2IdT6iKmPz9jeTz5g9Onx0Ng+8WUVMP2uc1uyjMEVV677q/k1Z+Ph
-----END EC PRIVATE KEY-----
`

//	go run generate_cert.go -ecdsa-curve P384 -host 127.0.0.1 -allowDC

var delegatorCertPEMP384 = `-----BEGIN CERTIFICATE-----
MIIBtzCCATygAwIBAgIQYhD6ucKVx53ZfdRCJkPy3DAKBggqhkjOPQQDAzASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTIxMDIyNzAwMTYzOFoXDTIyMDIyNzAwMTYzOFow
EjEQMA4GA1UEChMHQWNtZSBDbzB2MBAGByqGSM49AgEGBSuBBAAiA2IABHNmyki5
Xxfmxxrk4QRoXfU7hk0o2gJWTkCUAyzlVNcSaUTHub64v2cwn9/LbbooFBlhwz4n
n706yHtzmSQHTkCKmcG2LwS75U+ZajzPXKoSqazGhapBLQb7R7A+uRQGvqNXMFUw
DgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQC
MAAwDwYJKwYBBAGC2kssBAIFADAPBgNVHREECDAGhwR/AAABMAoGCCqGSM49BAMD
A2kAMGYCMQDIOr2c+CckkU48HqcFiyzPkYWUUeytqmzOg3QDOu6U0jfmi1Xb9dda
pytx77nIUucCMQDD9uVr1UeKGC3Iv0VIHw+tjBzTUg9iToG+PPIlnP+duIBjFQcl
FkeNmqTC8510USo=
-----END CERTIFICATE-----
`

var delegatorKeyPEMP384 = `-----BEGIN EC PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDA1ouSiH174RBEvZBch
QQnl5iYWTpdCa+EHjexYzhQ9HHMcU7nKCk7OXRod3kAVcUahZANiAARzZspIuV8X
5sca5OEEaF31O4ZNKNoCVk5AlAMs5VTXEmlEx7m+uL9nMJ/fy226KBQZYcM+J5+9
Osh7c5kkB05AipnBti8Eu+VPmWo8z1yqEqmsxoWqQS0G+0ewPrkUBr4=
-----END EC PRIVATE KEY-----
`

//	go run generate_cert.go -ecdsa-curve P521 -host 127.0.0.1 -allowDC

var delegatorCertPEMP521 = `-----BEGIN CERTIFICATE-----
MIICATCCAWKgAwIBAgIQJq2J2jQNbTUbhfjk0PT8/TAKBggqhkjOPQQDBDASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTIxMDIyNzAwMTcxN1oXDTIyMDIyNzAwMTcxN1ow
EjEQMA4GA1UEChMHQWNtZSBDbzCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEAM3n
1xAxRLYhnDNRqc0onmNM9Ik0Jcja6e0bYa9mo0oV/y5DPeML3UJB1CNImFpAkx62
wLiZmk/BhcPS0EstLAwXATBkb/q0fbKUZXFHd4gr5spRfAosXz5vg1VLeKHqpUku
tyJjgdFvuBZzmp2olqGKbBSKUElvDFkZWkZk5uGEnCsIo1cwVTAOBgNVHQ8BAf8E
BAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAPBgkrBgEE
AYLaSywEAgUAMA8GA1UdEQQIMAaHBH8AAAEwCgYIKoZIzj0EAwQDgYwAMIGIAkIB
TVEJrlJkxqs0adMPKg5D1EQDGy4dUz4YSWc0VXFOV7TKFDhjo1Abs3SYNXPsgAgT
Ol8BhJ2gFUhgHBP8BiJqPUYCQgFWXEe6AfKPyAUcNH28pIavfhxeGc0DGE4Xux0w
/vWpDdT89YxJmQC1roSaXRwEW1GBXL41h5rMMklGqkkfnCW2SQ==
-----END CERTIFICATE-----
`

var delegatorKeyPEMP521 = `-----BEGIN EC PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIA4X72HzMvgBj//dX/
SLkA2+oQ93l2eB2jXVRFST/mQj5NSSt8TNcIqW+TaxSejst7+jAQgnH2Zrith8zK
r2/Gy/6hgYkDgYYABADN59cQMUS2IZwzUanNKJ5jTPSJNCXI2untG2GvZqNKFf8u
Qz3jC91CQdQjSJhaQJMetsC4mZpPwYXD0tBLLSwMFwEwZG/6tH2ylGVxR3eIK+bK
UXwKLF8+b4NVS3ih6qVJLrciY4HRb7gWc5qdqJahimwUilBJbwxZGVpGZObhhJwr
CA==
-----END EC PRIVATE KEY-----
`

//	go run generate_cert.go -ed25519 -host 127.0.0.1 -allowDC

var delegatorCertPEMEd25519 = `-----BEGIN CERTIFICATE-----
MIIBOTCB7KADAgECAhEAzk3wRF7IPMF07CnnLbQEbDAFBgMrZXAwEjEQMA4GA1UE
ChMHQWNtZSBDbzAeFw0yMTAyMjcwMDE4MTVaFw0yMjAyMjcwMDE4MTVaMBIxEDAO
BgNVBAoTB0FjbWUgQ28wKjAFBgMrZXADIQD+aRKJTaCG+yEz/w3lLhglSTsxyPl4
FepwdCUXDxj2oKNXMFUwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUF
BwMBMAwGA1UdEwEB/wQCMAAwDwYJKwYBBAGC2kssBAIFADAPBgNVHREECDAGhwR/
AAABMAUGAytlcANBAO0XGRvpMAdkI8SVheJmr+Oe+BBR3VWyhU9PdIxiWu+v+pjp
UQDJpmto6r3AsriHVw2EIdvONnL1FeNzMX2HRAw=
-----END CERTIFICATE-----
`

var delegatorKeyPEMEd25519 = `-----BEGIN EC PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEILsRn/g0To97rbKf+2zV+sr6ZmrqcEiLRK2/rD7r+xDZ
-----END EC PRIVATE KEY-----
`

var nonDelegatorCertPEM = `-----BEGIN CERTIFICATE-----
MIIBaDCCAQ6gAwIBAgIQcMnAGu3NQYTGYf2HK+JodTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTIwMDgxODA1NDg1NloXDTIxMDgxODA1NDg1Nlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPAi
QzOthHUdwLTPo9P7Vk1I2W5RHW5nIkq9zYqqMZ5mHQ6vmmrpklvTNHtY93PlokjN
pnlhzEsxK/QrBoAQ8fajRjBEMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggr
BgEFBQcDATAMBgNVHRMBAf8EAjAAMA8GA1UdEQQIMAaHBH8AAAEwCgYIKoZIzj0E
AwIDSAAwRQIgbOxx7/KWTD47UTWIBcFB95BPrFp2SaFBUyjhzMDXsQkCIQDnwtye
V1OlcMigjCsQuGRacYFP3f1ASpYVv58t/ZeVCw==
-----END CERTIFICATE-----
`

var nonDelegatorKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgD9Q9131NamLDe4ud
dU9rg+gO0vv8lXYErf7P5GQlZD6hRANCAATwIkMzrYR1HcC0z6PT+1ZNSNluUR1u
ZyJKvc2KqjGeZh0Or5pq6ZJb0zR7WPdz5aJIzaZ5YcxLMSv0KwaAEPH2
-----END EC PRIVATE KEY-----
`

var (
	dcTestConfig *Config
	dcTestCerts  map[string]*Certificate

	serverDC    []DelegatedCredentialPair
	serverKEMDC []DelegatedCredentialPair
	serverPQDC  []DelegatedCredentialPair

	clientDC    []DelegatedCredentialPair
	clientKEMDC []DelegatedCredentialPair
	clientPQDC  []DelegatedCredentialPair

	dcNow                   time.Time
	dcTestDCSignatureScheme = []SignatureScheme{ECDSAWithP256AndSHA256, Ed25519, Ed448, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512}
	dcTestDCKEMScheme       = []SignatureScheme{KEMTLSWithSIKEp434, KEMTLSWithKyber512}
	dcTestDCPQScheme        = []SignatureScheme{PQTLSWithDilithium3, PQTLSWithDilithium4}
)

func init() {
	dcTestConfig = &Config{
		Time: func() time.Time {
			return dcNow
		},
		Rand:         zeroSource{},
		Certificates: nil,
		MinVersion:   VersionTLS10,
		MaxVersion:   VersionTLS13,
		CipherSuites: allCipherSuites(),
	}

}

func initDCTest() {
	// Use a static time for testing at which time the test certificates are
	// valid.
	dcNow = time.Date(2021, time.March, 31, 11, 0, 0, 234234, time.UTC)

	// The certificates of the server.
	dcTestCerts = make(map[string]*Certificate)
	var err error

	// The delegation P256 certificate.
	dcCertP256 := new(Certificate)
	*dcCertP256, err = X509KeyPair([]byte(delegatorCertPEMP256), []byte(delegatorKeyPEMP256))
	if err != nil {
		panic(err)
	}

	dcCertP256.Leaf, err = x509.ParseCertificate(dcCertP256.Certificate[0])
	if err != nil {
		panic(err)
	}
	dcTestCerts["dcP256"] = dcCertP256

	// The delegation P384 certificate.
	dcCertP384 := new(Certificate)
	*dcCertP384, err = X509KeyPair([]byte(delegatorCertPEMP384), []byte(delegatorKeyPEMP384))
	if err != nil {
		panic(err)
	}

	dcCertP384.Leaf, err = x509.ParseCertificate(dcCertP384.Certificate[0])
	if err != nil {
		panic(err)
	}
	dcTestCerts["dcP384"] = dcCertP384

	// The delegation P521 certificate.
	dcCertP521 := new(Certificate)
	*dcCertP521, err = X509KeyPair([]byte(delegatorCertPEMP521), []byte(delegatorKeyPEMP521))
	if err != nil {
		panic(err)
	}

	dcCertP521.Leaf, err = x509.ParseCertificate(dcCertP521.Certificate[0])
	if err != nil {
		panic(err)
	}
	dcTestCerts["dcP521"] = dcCertP521

	// The delegation Ed25519 certificate.
	dcCertEd25519 := new(Certificate)
	*dcCertEd25519, err = X509KeyPair([]byte(delegatorCertPEMEd25519), []byte(delegatorKeyPEMEd25519))
	if err != nil {
		panic(err)
	}

	dcCertEd25519.Leaf, err = x509.ParseCertificate(dcCertEd25519.Certificate[0])
	if err != nil {
		panic(err)
	}
	dcTestCerts["dcEd25519"] = dcCertEd25519

	// The non-delegation certificate.
	noDcCert := new(Certificate)
	*noDcCert, err = X509KeyPair([]byte(nonDelegatorCertPEM), []byte(nonDelegatorKeyPEM))
	if err != nil {
		panic(err)
	}
	noDcCert.Leaf, err = x509.ParseCertificate(noDcCert.Certificate[0])
	if err != nil {
		panic(err)
	}
	dcTestCerts["no dc"] = noDcCert

	// The root certificates for the peer.
	dcTestConfig.RootCAs = x509.NewCertPool()

	for _, c := range dcTestCerts {
		dcRoot, err := x509.ParseCertificate(c.Certificate[len(c.Certificate)-1])
		if err != nil {
			panic(err)
		}
		dcTestConfig.RootCAs.AddCert(dcRoot)
	}

	for i := 0; i < len(dcTestDCSignatureScheme); i++ {
		dc, priv, err := NewDelegatedCredential(dcCertP256, dcTestDCSignatureScheme[i], dcNow.Sub(dcCertP256.Leaf.NotBefore)+dcMaxTTL, false)
		if err != nil {
			panic(err)
		}
		serverDC = append(serverDC, DelegatedCredentialPair{dc, priv})

		dc, priv, err = NewDelegatedCredential(dcCertP256, dcTestDCSignatureScheme[i], dcNow.Sub(dcCertP256.Leaf.NotBefore)+dcMaxTTL, true)
		if err != nil {
			panic(err)
		}
		clientDC = append(clientDC, DelegatedCredentialPair{dc, priv})
	}

	for i := 0; i < len(dcTestDCKEMScheme); i++ {
		dc, priv, err := NewDelegatedCredential(dcCertP256, dcTestDCKEMScheme[i], dcNow.Sub(dcCertP256.Leaf.NotBefore)+dcMaxTTL, false)
		if err != nil {
			panic(err)
		}
		serverKEMDC = append(serverKEMDC, DelegatedCredentialPair{dc, priv})

		dc, priv, err = NewDelegatedCredential(dcCertP256, dcTestDCKEMScheme[i], dcNow.Sub(dcCertP256.Leaf.NotBefore)+dcMaxTTL, true)
		if err != nil {
			panic(err)
		}
		clientKEMDC = append(clientKEMDC, DelegatedCredentialPair{dc, priv})
	}

	for i := 0; i < len(dcTestDCPQScheme); i++ {
		dc, priv, err := NewDelegatedCredential(dcCertP256, dcTestDCPQScheme[i], dcNow.Sub(dcCertP256.Leaf.NotBefore)+dcMaxTTL, false)
		if err != nil {
			panic(err)
		}
		serverPQDC = append(serverPQDC, DelegatedCredentialPair{dc, priv})

		dc, priv, err = NewDelegatedCredential(dcCertP256, dcTestDCPQScheme[i], dcNow.Sub(dcCertP256.Leaf.NotBefore)+dcMaxTTL, true)
		if err != nil {
			panic(err)
		}
		clientPQDC = append(clientPQDC, DelegatedCredentialPair{dc, priv})
	}
}

func publicKeysEqual(publicKey, publicKey2 crypto.PublicKey, algo SignatureScheme) error {
	switch publicKey.(type) {
	case *ecdsa.PublicKey:
		curve := getECDSACurve(algo)
		pk := publicKey.(*ecdsa.PublicKey)
		pk2 := publicKey2.(*ecdsa.PublicKey)

		serPubKey := elliptic.Marshal(curve, pk.X, pk.Y)
		serPubKey2 := elliptic.Marshal(curve, pk2.X, pk2.Y)
		if !bytes.Equal(serPubKey2, serPubKey) {
			return errors.New("ecdsa public Keys mismatch")
		}
	case ed25519.PublicKey:
		pk := publicKey.(ed25519.PublicKey)
		pk2 := publicKey2.(ed25519.PublicKey)

		if !bytes.Equal(pk, pk2) {
			return errors.New("ed25519 Public Keys mismatch")
		}
	}

	return nil
}

func delegagedCredentialsEqual(dc, dc2 *DelegatedCredential) error {
	if dc2.cred.validTime != dc.cred.validTime {
		return fmt.Errorf("ValidTime mismatch: got %d; want %d", dc2.cred.validTime, dc.cred.validTime)
	}

	if dc2.cred.expCertVerfAlgo != dc.cred.expCertVerfAlgo {
		return fmt.Errorf("scheme mismatch: got %04x; want %04x", dc2.cred.expCertVerfAlgo, dc.cred.expCertVerfAlgo)
	}

	return publicKeysEqual(dc.cred.publicKey, dc2.cred.publicKey, dc.cred.expCertVerfAlgo)
}

// Test delegation and validation of credentials.
func TestDelegateCredentialsValidate(t *testing.T) {
	initDCTest()
	cert := dcTestCerts["dcP384"]
	validTime := dcNow.Sub(cert.Leaf.NotBefore) + dcMaxTTL

	delegatedCred, _, err := NewDelegatedCredential(cert, ECDSAWithP384AndSHA384, validTime, false)
	if err != nil {
		t.Fatal(err)
	} else if delegatedCred == nil {
		t.Fatal("unable to generate a Delegated Credential")
	}

	rand := rand.New(rand.NewSource(time.Now().UnixNano()))
	m := &certificateVerifyMsg{}
	m.hasSignatureAlgorithm = true
	m.signatureAlgorithm = ECDSAWithP384AndSHA384
	m.signature = randomBytes(rand.Intn(15)+1, rand)

	// Valid Delegated Credential
	if !delegatedCred.Validate(cert.Leaf, false, dcNow, m) {
		t.Error("generated valid Delegated Credential is rendered invalid")
	}

	// Expired Delegated Credential
	expired := dcNow.Add(dcMaxTTL).Add(time.Nanosecond)
	if delegatedCred.Validate(cert.Leaf, false, expired, m) {
		t.Error("expired delegated credential is valid; want invalid")
	}

	// Test validation of Delegated Credential which TTL is too long
	invalidDelegatedCred, _, err := NewDelegatedCredential(cert, ECDSAWithP384AndSHA384, validTime+time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	if invalidDelegatedCred.Validate(cert.Leaf, false, dcNow, m) {
		t.Error("Delegated Credential validation with long TTL succeeded; want failure")
	}

	shortValidTime := dcNow.Sub(cert.Leaf.NotBefore) + time.Second

	// Test validation of Delegated Credential which TTL is short
	delegatedCred, _, err = NewDelegatedCredential(cert, ECDSAWithP384AndSHA384, shortValidTime, false)
	if err != nil {
		t.Fatal(err)
	}
	if !delegatedCred.Validate(cert.Leaf, false, dcNow, m) {
		t.Error("valid Delegated Credential is invalid; want valid")
	}

	delegatedCred.algorithm = ECDSAWithP521AndSHA512

	// Test signature algorithm binding
	if delegatedCred.Validate(cert.Leaf, false, dcNow, m) {
		t.Error("Delegated Credential with wrong scheme is valid; want invalid")
	}

	delegatedCred.algorithm = ECDSAWithP384AndSHA384

	// Test delegation certificate binding
	cert.Leaf.Raw[0] ^= byte(42)
	if delegatedCred.Validate(cert.Leaf, false, dcNow, m) {
		t.Error("Delegated Credential with wrong certificate is valid; want invalid")
	}

	// Test validation of DC using a certificate that can't delegate.
	if delegatedCred.Validate(dcTestCerts["no dc"].Leaf, false, dcNow, m) {
		t.Error("Delegated Credential with non-delegation cert is valid; want invalid")
	}

	// Test DC with another certificate
	cert = dcTestCerts["dcP521"]
	validTime = dcNow.Sub(cert.Leaf.NotBefore) + dcMaxTTL
	delegatedCred, _, err = NewDelegatedCredential(cert, ECDSAWithP384AndSHA384, validTime, false)
	if err != nil {
		t.Fatal(err)
	} else if delegatedCred == nil {
		t.Fatal("unable to generate a Delegated Credential")
	}

	// Valid Delegated Credential
	if !delegatedCred.Validate(cert.Leaf, false, dcNow, m) {
		t.Error("generated valid Delegated Credential is rendered invalid")
	}
}

// Test encoding/decoding of Delegated Credentials.
func TestDelegatedCredentialMarshal(t *testing.T) {
	initDCTest()
	cert := dcTestCerts["dcEd25519"]
	time := dcNow.Sub(cert.Leaf.NotBefore) + dcMaxTTL

	for _, sig := range dcTestDCSignatureScheme {
		delegatedCred, _, err := NewDelegatedCredential(cert, sig, time, false)
		if err != nil {
			t.Fatal(err)
		}

		ser, err := delegatedCred.marshal()
		if err != nil {
			t.Error(err)
		}

		delegatedCred2, err := unmarshalDelegatedCredential(ser)
		if err != nil {
			t.Error(err)
		}

		err = delegagedCredentialsEqual(delegatedCred, delegatedCred2)
		if err != nil {
			t.Error(err)
		}

		if delegatedCred.algorithm != delegatedCred2.algorithm {
			t.Errorf("scheme mismatch: got %04x; want %04x", delegatedCred2.algorithm, delegatedCred.algorithm)
		}

		if !bytes.Equal(delegatedCred2.signature, delegatedCred.signature) {
			t.Error("Signature mismatch")
		}
	}
}

var dcServerTests = []struct {
	clientDCSupport bool
	clientMaxVers   uint16
	serverMaxVers   uint16
	expectSuccess   bool
	expectDC        bool
	name            string
}{
	{true, VersionTLS13, VersionTLS13, true, true, "tls13: DC client support"},
	{false, VersionTLS13, VersionTLS13, true, false, "DC not client support"},
	{true, VersionTLS12, VersionTLS13, true, false, "client using TLS 1.2. No DC is supported in that version."},
	{true, VersionTLS13, VersionTLS12, true, false, "server using TLS 1.2. No DC is supported in that version."},
	{true, VersionTLS11, VersionTLS13, true, false, "client using TLS 1.1. No DC is supported in that version."},
	{true, VersionTLS13, VersionTLS10, false, false, "server using TLS 1.0. No DC is supported in that version."},
}

var dcClientTests = []struct {
	serverDCSupport bool
	clientMaxVers   uint16
	serverMaxVers   uint16
	expectSuccess   bool
	expectDC        bool
	name            string
}{
	{true, VersionTLS13, VersionTLS13, true, true, "tls13: DC server support"},
	{false, VersionTLS13, VersionTLS13, true, false, "DC not server support"},
	{true, VersionTLS12, VersionTLS13, true, false, "client using TLS 1.2. No DC is supported in that version."},
	{true, VersionTLS13, VersionTLS12, true, false, "server using TLS 1.2. No DC is supported in that version."},
	{true, VersionTLS11, VersionTLS13, true, false, "client using TLS 1.1. No DC is supported in that version."},
	{true, VersionTLS13, VersionTLS10, false, false, "server using TLS 1.0. No DC is supported in that version."},
}

// dcCount defines the delegated credential to be used as returned by the
// getCertificate or getClientCertificate callback. This allows to use
// delegated credentials with different algorithms at each run of the
// tests.
var dcCount int

// Checks that the client suppports a version >= 1.3 and accepts Delegated
// Credentials. If so, it returns the delegation certificate; otherwise it
// returns a non-delegated certificate.
func testServerGetCertificate(ch *ClientHelloInfo) (*Certificate, error) {
	versOk := false
	for _, vers := range ch.SupportedVersions {
		versOk = versOk || (vers >= uint16(VersionTLS13))
	}

	if versOk && ch.SupportsDelegatedCredential {
		serverCert := dcTestCerts["dcP256"]
		serverCert.DelegatedCredentials = serverDC[dcCount:]
		return serverCert, nil
	}
	return dcTestCerts["no dc"], nil

}

// Checks that the client suppports a version >= 1.3 and accepts Delegated
// Credentials. If so, it returns the delegation certificate; otherwise it
// returns a non-Delegated certificate.
func testClientGetCertificate(cr *CertificateRequestInfo) (*Certificate, error) {
	versOk := false
	if cr.Version == VersionTLS13 {
		versOk = true
	}

	if versOk && cr.SupportsDelegatedCredential {
		clientCert := dcTestCerts["dcP256"]
		clientCert.DelegatedCredentials = clientDC[dcCount:]
		return clientCert, nil
	}
	return dcTestCerts["no dc"], nil

}

// Tests the handshake and one round of application data. Returns true if the
// connection correctly used a Delegated Credential.
func testConnWithDC(t *testing.T, clientMsg, serverMsg string, clientConfig, serverConfig *Config, peer string, kemtls bool, pqtls bool) (usedDC bool, usedKEMTLS bool, usedPQTLS bool, serverState, clientState ConnectionState, err error) {
	ln := newLocalListener(t)
	defer ln.Close()

	serverCh := make(chan *Conn, 1)
	var serverErr error
	go func() {
		serverConn, err := ln.Accept()
		if err != nil {
			serverErr = err
			serverCh <- nil
			return
		}
		server := Server(serverConn, serverConfig)
		if err := server.Handshake(); err != nil {
			serverErr = fmt.Errorf("handshake error: %v", err)
			serverCh <- nil
			return
		}
		serverCh <- server
	}()
	var state ConnectionState
	client, err := Dial("tcp", ln.Addr().String(), clientConfig)
	if err != nil {
		return false, false, false, state, state, err
	}
	defer client.Close()

	server := <-serverCh
	if server == nil {
		return false, false, false, state, state, serverErr
	}

	bufLen := len(clientMsg)
	if len(serverMsg) > len(clientMsg) {
		bufLen = len(serverMsg)
	}
	buf := make([]byte, bufLen)

	client.Write([]byte(clientMsg))
	n, err := server.Read(buf)
	if err != nil || n != len(clientMsg) || string(buf[:n]) != clientMsg {
		return false, false, false, state, state, fmt.Errorf("Server read = %d, buf= %q; want %d, %s", n, buf, len(clientMsg), clientMsg)
	}

	server.Write([]byte(serverMsg))
	n, err = client.Read(buf)
	if n != len(serverMsg) || err != nil || string(buf[:n]) != serverMsg {
		return false, false, false, state, state, fmt.Errorf("Client read = %d, %v, data %q; want %d, nil, %s", n, err, buf, len(serverMsg), serverMsg)
	}

	if kemtls {
		if peer == "server" {
			return (server.verifiedDC != nil), (server.didKEMTLS && client.didKEMTLS), false, server.ConnectionState(), client.ConnectionState(), nil
		} else if peer == "client" {
			return (client.verifiedDC != nil), (server.didKEMTLS && client.didKEMTLS), false, server.ConnectionState(), client.ConnectionState(), nil
		} else if peer == "both" {
			return (client.verifiedDC != nil && server.verifiedDC != nil), (server.didKEMTLS && client.didKEMTLS), false, server.ConnectionState(), client.ConnectionState(), nil
		}
	} else if pqtls {
		if peer == "server" {
			return (server.verifiedDC != nil), false, (server.didPQTLS && client.didPQTLS), state, state, nil
		} else if peer == "client" {
			return (client.verifiedDC != nil), false, (server.didPQTLS && client.didPQTLS), state, state, nil
		} else if peer == "both" {
			return (client.verifiedDC != nil && server.verifiedDC != nil), false, (server.didPQTLS && client.didPQTLS), state, state, nil
		}

	} else {
		if peer == "server" {
			return (server.verifiedDC != nil), false, false, state, state, nil
		} else if peer == "client" {
			return (client.verifiedDC != nil), false, false, state, state, nil
		} else if peer == "both" {
			return (client.verifiedDC != nil && server.verifiedDC != nil), false, false, state, state, nil
		}
	}

	return false, false, false, state, state, nil
}

func testServerConnWithDC(t *testing.T, clientMsg, serverMsg, addr string, serverConfig *Config, kemtls bool, pqtls bool) (usedDC bool, usedKEMTLS bool, usedPQTLS bool, serverState ConnectionState, err error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverCh := make(chan *Conn, 1)
	var serverErr error
	go func() {
		serverConn, err := ln.Accept()
		if err != nil {
			serverErr = err
			serverCh <- nil
			return
		}
		server := Server(serverConn, serverConfig)
		if err := server.Handshake(); err != nil {
			serverErr = fmt.Errorf("handshake error: %v", err)
			serverCh <- nil
			return
		}
		serverCh <- server
	}()
	var state ConnectionState
	server := <-serverCh
	if server == nil {
		return false, false, false, state, serverErr
	}

	bufLen := len(clientMsg)
	if len(serverMsg) > len(clientMsg) {
		bufLen = len(serverMsg)
	}
	buf := make([]byte, bufLen)

	n, err := server.Read(buf)
	if err != nil || n != len(clientMsg) || string(buf[:n]) != clientMsg {
		return false, false, false, state, fmt.Errorf("Server read = %d, buf= %q; want %d, %s", n, buf, len(clientMsg), clientMsg)
	}

	server.Write([]byte(serverMsg))
	if kemtls {
		return (server.verifiedDC != nil), server.didKEMTLS, false, server.ConnectionState(), nil
	} else if pqtls {
		return (server.verifiedDC != nil), false, server.didPQTLS, state, nil
	} else {
		return (server.verifiedDC != nil), false, false, state, nil
	}

	return false, false, false, state, nil
}

func testClientConnWithDC(t *testing.T, clientMsg, addr string, clientConfig *Config, serverMsg string, kemtls bool, pqtls bool) (usedDC bool, usedKEMTLS bool, usedPQTLS bool, clientState ConnectionState, err error) {
	var state ConnectionState
	client, err := Dial("tcp", addr, clientConfig)
	if err != nil {
		return false, false, false, state, err
	}
	defer client.Close()
	bufLen := len(clientMsg)
	buf := make([]byte, bufLen)
	client.Write([]byte(clientMsg))
	n, err := client.Read(buf)
	if n != len(serverMsg) || err != nil || string(buf[:n]) != serverMsg {
		return false, false, false, state, fmt.Errorf("Client read = %d, %v, data %q; want %d, nil, %s", n, err, buf, len(serverMsg), serverMsg)
	}

	if kemtls {
		return (client.verifiedDC != nil), client.didKEMTLS, false, client.ConnectionState(), nil
	} else if pqtls {
		return (client.verifiedDC != nil), false, client.didPQTLS, state, nil
	} else {
		return (client.verifiedDC != nil), false, false, state, nil
	}
	return false, false, false, state, nil
}

// Test the server authentication with the Delegated Credential extension.
func TestDCHandshakeServerAuth(t *testing.T) {
	serverMsg := "hello, client"
	clientMsg := "hello, server"

	clientConfig := dcTestConfig.Clone()
	serverConfig := dcTestConfig.Clone()
	clientConfig.InsecureSkipVerify = true

	for i, test := range dcServerTests {
		clientConfig.SupportDelegatedCredential = test.clientDCSupport

		for dcCount = 0; dcCount < len(dcTestDCSignatureScheme); dcCount++ {
			initDCTest()
			serverConfig.GetCertificate = testServerGetCertificate
			clientConfig.MaxVersion = test.clientMaxVers
			serverConfig.MaxVersion = test.serverMaxVers
			usedDC, _, _, _, _, err := testConnWithDC(t, clientMsg, serverMsg, clientConfig, serverConfig, "client", false, false)

			if err != nil && test.expectSuccess {
				t.Errorf("test #%d (%s) with signature algorithm #%d fails: %s", i, test.name, dcCount, err.Error())
			} else if err == nil && !test.expectSuccess {
				t.Errorf("test #%d (%s) with signature algorithm #%d succeeds; expected failure", i, test.name, dcCount)
			}

			if usedDC != test.expectDC {
				t.Errorf("test #%d (%s) with signature algorithm #%d usedDC = %v; expected %v", i, test.name, dcCount, usedDC, test.expectDC)
			}
		}
	}
}

// Test the client authentication with the Delegated Credential extension.
func TestDCHandshakeClientAuth(t *testing.T) {
	clientMsg := "hello, server"
	serverMsg := "hello, client"

	serverConfig := dcTestConfig.Clone()
	serverConfig.ClientAuth = RequestClientCert
	serverConfig.GetCertificate = testServerGetCertificate
	clientConfig := dcTestConfig.Clone()
	clientConfig.GetClientCertificate = testClientGetCertificate

	for j, test := range dcClientTests {
		serverConfig.SupportDelegatedCredential = test.serverDCSupport

		for dcCount = 0; dcCount < len(dcTestDCSignatureScheme); dcCount++ {
			initDCTest()
			serverConfig.MaxVersion = test.serverMaxVers
			clientConfig.MaxVersion = test.clientMaxVers

			usedDC, _, _, _, _, err := testConnWithDC(t, clientMsg, serverMsg, clientConfig, serverConfig, "server", false, false)

			if err != nil && test.expectSuccess {
				t.Errorf("test #%d (%s) with signature algorithm #%d fails: %s", j, test.name, dcCount, err.Error())
			} else if err == nil && !test.expectSuccess {
				t.Errorf("test #%d (%s) with signature algorithm #%d succeeds; expected failure", j, test.name, dcCount)
			}

			if usedDC != test.expectDC {
				t.Errorf("test #%d (%s) with signature algorithm #%d usedDC = %v; expected %v", j, test.name, dcCount, usedDC, test.expectDC)
			}
		}
	}
}

// Test server and client authentication with the Delegated Credential extension.
func TestDCHandshakeClientAndServerAuth(t *testing.T) {
	clientMsg := "hello, server"
	serverMsg := "hello, client"

	serverConfig := dcTestConfig.Clone()
	serverConfig.ClientAuth = RequestClientCert
	serverConfig.GetCertificate = testServerGetCertificate
	clientConfig := dcTestConfig.Clone()
	clientConfig.GetClientCertificate = testClientGetCertificate

	serverConfig.SupportDelegatedCredential = true
	clientConfig.SupportDelegatedCredential = true

	serverConfig.MaxVersion = VersionTLS13
	clientConfig.MaxVersion = VersionTLS13

	initDCTest()

	usedDC, _, _, _, _, err := testConnWithDC(t, clientMsg, serverMsg, clientConfig, serverConfig, "both", false, false)

	if err != nil {
		t.Errorf("test server and client auth fails: %s", err.Error())
	}

	if usedDC != true {
		t.Errorf("test server and client auth does not succeed")
	}
}

var dcKEMServerTests = []struct {
	clientDCSupport bool
	clientMaxVers   uint16
	serverMaxVers   uint16
	expectSuccess   bool
	expectDC        bool
	name            string
}{
	{true, VersionTLS13, VersionTLS13, true, true, "tls13: DC client support"},
	{false, VersionTLS13, VersionTLS13, false, false, "DC not client support"},
	{true, VersionTLS12, VersionTLS13, false, false, "client using TLS 1.2. No DC is supported in that version."},
	{true, VersionTLS13, VersionTLS12, false, false, "server using TLS 1.2. No DC is supported in that version."},
	{true, VersionTLS11, VersionTLS13, false, false, "client using TLS 1.1. No DC is supported in that version."},
	{true, VersionTLS13, VersionTLS10, false, false, "server using TLS 1.0. No DC is supported in that version."},
}

var dcKEMClientTests = []struct {
	serverDCSupport bool
	clientMaxVers   uint16
	serverMaxVers   uint16
	expectSuccess   bool
	expectDC        bool
	name            string
}{
	{true, VersionTLS13, VersionTLS13, true, true, "tls13: DC server support"},
	{true, VersionTLS13, VersionTLS12, false, false, "server using TLS 1.2. No DC is supported in that version."},
	{true, VersionTLS11, VersionTLS13, false, false, "client using TLS 1.1. No DC is supported in that version."},
	{true, VersionTLS13, VersionTLS10, false, false, "server using TLS 1.0. No DC is supported in that version."},
}

// Checks that the client suppports a version >= 1.3 and accepts Delegated
// Credentials with KEMs. If so, it returns the delegation certificate; otherwise it
// returns a non-delegated certificate.
func testServerGetKEMCertificate(ch *ClientHelloInfo) (*Certificate, error) {
	versOk := false
	for _, vers := range ch.SupportedVersions {
		versOk = versOk || (vers >= uint16(VersionTLS13))
	}

	if versOk && ch.SupportsDelegatedCredential {
		serverCert := dcTestCerts["dcP256"]
		serverCert.DelegatedCredentials = serverKEMDC[dcCount:]
		return serverCert, nil
	}
	return dcTestCerts["no dc"], nil

}

// Checks that the client suppports a version >= 1.3 and accepts Delegated
// Credentials with KEMs. If so, it returns the delegation certificate; otherwise it
// returns a non-Delegated certificate.
func testClientGetKEMCertificate(cr *CertificateRequestInfo) (*Certificate, error) {
	versOk := false
	if cr.Version == VersionTLS13 {
		versOk = true
	}

	if versOk && cr.SupportsDelegatedCredential {
		clientCert := dcTestCerts["dcP256"]
		clientCert.DelegatedCredentials = clientKEMDC[dcCount:]
		return clientCert, nil
	}
	return dcTestCerts["no dc"], nil

}

// Test the server authentication with the Delegated Credential extension using
// KEMs.
func TestDCKEMHandshakeServerAuth(t *testing.T) {
	serverMsg := "hello, client"
	clientMsg := "hello, server"

	clientConfig := dcTestConfig.Clone()
	serverConfig := dcTestConfig.Clone()
	clientConfig.KEMTLSEnabled = true
	serverConfig.KEMTLSEnabled = true
	clientConfig.CurvePreferences = []CurveID{Kyber512, SIKEp434}
	serverConfig.CurvePreferences = []CurveID{Kyber512, SIKEp434}
	clientConfig.InsecureSkipVerify = true

	for i, test := range dcKEMServerTests {
		clientConfig.SupportDelegatedCredential = test.clientDCSupport

		for dcCount = 0; dcCount < len(dcTestDCKEMScheme); dcCount++ {
			initDCTest()
			serverConfig.GetCertificate = testServerGetKEMCertificate
			clientConfig.MaxVersion = test.clientMaxVers
			serverConfig.MaxVersion = test.serverMaxVers
			usedDC, usedKEMTLS, _, _, _, err := testConnWithDC(t, clientMsg, serverMsg, clientConfig, serverConfig, "client", true, false)

			if err != nil && test.expectSuccess {
				t.Errorf("test #%d (%s) with kem #%d fails: %s", i, test.name, dcCount, err.Error())
			} else if err == nil && !test.expectSuccess {
				t.Errorf("test #%d (%s) with kem #%d succeeds; expected failure", i, test.name, dcCount)
			}

			if usedDC != test.expectDC {
				t.Errorf("test #%d (%s) with kem #%d usedDC = %v; expected %v", i, test.name, dcCount, usedDC, test.expectDC)
			}

			if !usedKEMTLS && test.expectSuccess {
				t.Errorf("test #%d (%s) with kem #%d did not use kemtls", i, test.name, dcCount)
			}
		}
	}
}

// Test the client authentication with the Delegated Credential extension with
// KEMs.
func TestDCKEMHandshakeClientAuth(t *testing.T) {
	clientMsg := "hello, server"
	serverMsg := "hello, client"

	serverConfig := dcTestConfig.Clone()
	serverConfig.ClientAuth = RequestClientCert
	serverConfig.GetCertificate = testServerGetKEMCertificate
	serverConfig.KEMTLSEnabled = true
	serverConfig.CurvePreferences = []CurveID{SIKEp434, Kyber512}

	clientConfig := dcTestConfig.Clone()
	clientConfig.GetClientCertificate = testClientGetKEMCertificate
	clientConfig.SupportDelegatedCredential = true // to force the sending of a KEM DC
	clientConfig.KEMTLSEnabled = true
	clientConfig.CurvePreferences = []CurveID{SIKEp434, Kyber512}

	for i, test := range dcKEMClientTests {
		serverConfig.SupportDelegatedCredential = test.serverDCSupport

		for dcCount = 0; dcCount < len(dcTestDCKEMScheme); dcCount++ {
			initDCTest()
			serverConfig.MaxVersion = test.serverMaxVers
			clientConfig.MaxVersion = test.clientMaxVers

			usedDC, usedKEMTLS, _, _, _, err := testConnWithDC(t, clientMsg, serverMsg, clientConfig, serverConfig, "server", true, false)

			if err != nil && test.expectSuccess {
				t.Errorf("test #%d (%s) with kem algorithm #%d fails: %s", i, test.name, dcCount, err.Error())
			} else if err == nil && !test.expectSuccess {
				t.Errorf("test #%d (%s) with kem algorithm #%d succeeds; expected failure", i, test.name, dcCount)
			}

			if usedDC != test.expectDC {
				t.Errorf("test #%d (%s) with kem algorithm #%d usedDC = %v; expected %v", i, test.name, dcCount, usedDC, test.expectDC)
			}

			if !usedKEMTLS && test.expectSuccess {
				t.Errorf("test #%d (%s) with kem #%d did not use kemtls", i, test.name, dcCount)
			}
		}
	}
}

// Test server and client authentication with the Delegated Credential extension with kems.
func TestDCKEMHandshakeClientAndServerAuth(t *testing.T) {
	clientMsg := "hello, server"
	serverMsg := "hello, client"

	serverConfig := dcTestConfig.Clone()
	serverConfig.ClientAuth = RequestClientCert
	serverConfig.GetCertificate = testServerGetKEMCertificate
	clientConfig := dcTestConfig.Clone()
	clientConfig.GetClientCertificate = testClientGetKEMCertificate
	clientConfig.KEMTLSEnabled = true
	serverConfig.KEMTLSEnabled = true
	clientConfig.CurvePreferences = []CurveID{Kyber512}
	serverConfig.CurvePreferences = []CurveID{Kyber512}

	serverConfig.SupportDelegatedCredential = true
	clientConfig.SupportDelegatedCredential = true

	serverConfig.MaxVersion = VersionTLS13
	clientConfig.MaxVersion = VersionTLS13

	initDCTest()

	usedDC, usedKEMTLS, _, _, _, err := testConnWithDC(t, clientMsg, serverMsg, clientConfig, serverConfig, "both", true, false)

	if err != nil {
		t.Errorf("test server and client auth with kems fails: %s", err.Error())
	}

	if usedDC != true {
		t.Errorf("test server and client auth with kems does not succeed")
	}

	if !usedKEMTLS {
		t.Errorf("test server and client auth with kems did not use kemtls")
	}
}

// Test server and client authentication with the Delegated Credential extension with kems and cached information.
func TestDCKEMCachedInfoHandshakeServerAuth(t *testing.T) {
	clientMsg := "hello, server"
	serverMsg := "hello, client"

	serverConfig := dcTestConfig.Clone()
	serverConfig.GetCertificate = testServerGetKEMCertificate
	clientConfig := dcTestConfig.Clone()
	clientConfig.GetClientCertificate = testClientGetKEMCertificate
	clientConfig.KEMTLSEnabled = true
	serverConfig.KEMTLSEnabled = true
	clientConfig.CurvePreferences = []CurveID{Kyber512}
	serverConfig.CurvePreferences = []CurveID{Kyber512}

	serverConfig.SupportDelegatedCredential = true
	clientConfig.SupportDelegatedCredential = true

	serverConfig.MaxVersion = VersionTLS13
	clientConfig.MaxVersion = VersionTLS13

	initDCTest()

	usedDC, usedKEMTLS, _, _, clientState, err := testConnWithDC(t, clientMsg, serverMsg, clientConfig, serverConfig, "client", true, false)

	if err != nil {
		t.Errorf("test server and client auth with kems fails: %s", err.Error())
	}

	if usedDC != true {
		t.Errorf("test server and client auth with kems does not succeed")
	}

	if !usedKEMTLS {
		t.Errorf("test server and client auth with kems did not use kemtls")
	}

	clientConfig.CachedCert = clientState.CertificateMessage
	clientConfig.CachedCertReq = clientState.CertificateReqMessage

	usedDC, usedKEMTLS, _, _, _, err = testConnWithDC(t, clientMsg, serverMsg, clientConfig, serverConfig, "client", true, false)

	if err != nil {
		t.Errorf("test server and client auth with kems fails: %s", err.Error())
	}

	if usedDC != true {
		t.Errorf("test server and client auth with kems does not succeed")
	}

	if !usedKEMTLS {
		t.Errorf("test server and client auth with kems did not use kemtls")
	}
}

var dcPQServerTests = []struct {
	clientDCSupport bool
	clientMaxVers   uint16
	serverMaxVers   uint16
	expectSuccess   bool
	expectDC        bool
	name            string
}{
	{true, VersionTLS13, VersionTLS13, true, true, "tls13: DC client support"},
	{false, VersionTLS13, VersionTLS13, false, false, "DC not client support"},
	{true, VersionTLS12, VersionTLS13, false, false, "client using TLS 1.2. No DC is supported in that version."},
	{true, VersionTLS13, VersionTLS12, false, false, "server using TLS 1.2. No DC is supported in that version."},
	{true, VersionTLS11, VersionTLS13, false, false, "client using TLS 1.1. No DC is supported in that version."},
	{true, VersionTLS13, VersionTLS10, false, false, "server using TLS 1.0. No DC is supported in that version."},
}

var dcPQClientTests = []struct {
	serverDCSupport bool
	clientMaxVers   uint16
	serverMaxVers   uint16
	expectSuccess   bool
	expectDC        bool
	name            string
}{
	{true, VersionTLS13, VersionTLS13, true, true, "tls13: DC server support"},
	{true, VersionTLS13, VersionTLS12, false, false, "server using TLS 1.2. No DC is supported in that version."},
	{true, VersionTLS11, VersionTLS13, false, false, "client using TLS 1.1. No DC is supported in that version."},
	{true, VersionTLS13, VersionTLS10, false, false, "server using TLS 1.0. No DC is supported in that version."},
}

// Checks that the client suppports a version >= 1.3 and accepts Delegated
// Credentials with KEMs. If so, it returns the delegation certificate; otherwise it
// returns a non-delegated certificate.
func testServerGetPQCertificate(ch *ClientHelloInfo) (*Certificate, error) {
	versOk := false
	for _, vers := range ch.SupportedVersions {
		versOk = versOk || (vers >= uint16(VersionTLS13))
	}

	if versOk && ch.SupportsDelegatedCredential {
		serverCert := dcTestCerts["dcP256"]
		serverCert.DelegatedCredentials = serverPQDC[dcCount:]
		return serverCert, nil
	}
	return dcTestCerts["no dc"], nil

}

// Checks that the client suppports a version >= 1.3 and accepts Delegated
// Credentials with KEMs. If so, it returns the delegation certificate; otherwise it
// returns a non-Delegated certificate.
func testClientGetPQCertificate(cr *CertificateRequestInfo) (*Certificate, error) {
	versOk := false
	if cr.Version == VersionTLS13 {
		versOk = true
	}

	if versOk && cr.SupportsDelegatedCredential {
		clientCert := dcTestCerts["dcP256"]
		clientCert.DelegatedCredentials = clientPQDC[dcCount:]
		return clientCert, nil
	}
	return dcTestCerts["no dc"], nil

}

// Test the server authentication with the Delegated Credential extension using
// PQTLS.
func TestDCPQHandshakeServerAuth(t *testing.T) {
	serverMsg := "hello, client"
	clientMsg := "hello, server"

	clientConfig := dcTestConfig.Clone()
	serverConfig := dcTestConfig.Clone()
	clientConfig.PQTLSEnabled = true
	serverConfig.PQTLSEnabled = true
	clientConfig.CurvePreferences = []CurveID{Kyber512, SIKEp434}
	serverConfig.CurvePreferences = []CurveID{Kyber512, SIKEp434}
	clientConfig.InsecureSkipVerify = true

	for i, test := range dcKEMServerTests {
		clientConfig.SupportDelegatedCredential = test.clientDCSupport

		for dcCount = 0; dcCount < len(dcTestDCPQScheme); dcCount++ {
			initDCTest()
			serverConfig.GetCertificate = testServerGetPQCertificate
			clientConfig.MaxVersion = test.clientMaxVers
			serverConfig.MaxVersion = test.serverMaxVers

			usedDC, _, usedPQTLS, _, _, err := testConnWithDC(t, clientMsg, serverMsg, clientConfig, serverConfig, "client", false, true)

			if err != nil && test.expectSuccess {
				t.Errorf("test #%d (%s) with pq #%d fails: %s", i, test.name, dcCount, err.Error())
			} else if err == nil && !test.expectSuccess {
				t.Errorf("test #%d (%s) with pq #%d succeeds; expected failure", i, test.name, dcCount)
			}

			if usedDC != test.expectDC {
				t.Errorf("test #%d (%s) with pq #%d usedDC = %v; expected %v", i, test.name, dcCount, usedDC, test.expectDC)
			}

			if !usedPQTLS && test.expectSuccess {
				t.Errorf("test #%d (%s) with pq #%d did not use pqtls", i, test.name, dcCount)
			}
		}
	}
}

// Test the client authentication with the Delegated Credential extension with
// PQTLS.
func TestDCPQHandshakeClientAuth(t *testing.T) {
	clientMsg := "hello, server"
	serverMsg := "hello, client"

	serverConfig := dcTestConfig.Clone()
	serverConfig.ClientAuth = RequestClientCert
	serverConfig.GetCertificate = testServerGetPQCertificate
	serverConfig.PQTLSEnabled = true
	serverConfig.CurvePreferences = []CurveID{SIKEp434, Kyber512}

	clientConfig := dcTestConfig.Clone()
	clientConfig.GetClientCertificate = testClientGetPQCertificate
	clientConfig.SupportDelegatedCredential = true // to force the sending of a PQ DC
	clientConfig.PQTLSEnabled = true
	clientConfig.CurvePreferences = []CurveID{SIKEp434, Kyber512}

	for i, test := range dcPQClientTests {
		serverConfig.SupportDelegatedCredential = test.serverDCSupport

		for dcCount = 0; dcCount < len(dcTestDCPQScheme); dcCount++ {
			initDCTest()
			serverConfig.MaxVersion = test.serverMaxVers
			clientConfig.MaxVersion = test.clientMaxVers

			usedDC, _, usedPQTLS, _, _, err := testConnWithDC(t, clientMsg, serverMsg, clientConfig, serverConfig, "server", false, true)

			if err != nil && test.expectSuccess {
				t.Errorf("test #%d (%s) with pq algorithm #%d fails: %s", i, test.name, dcCount, err.Error())
			} else if err == nil && !test.expectSuccess {
				t.Errorf("test #%d (%s) with pq algorithm #%d succeeds; expected failure", i, test.name, dcCount)
			}

			if usedDC != test.expectDC {
				t.Errorf("test #%d (%s) with pq algorithm #%d usedDC = %v; expected %v", i, test.name, dcCount, usedDC, test.expectDC)
			}

			if !usedPQTLS && test.expectSuccess {
				t.Errorf("test #%d (%s) with pqs #%d did not use pqtls", i, test.name, dcCount)
			}
		}
	}
}

// Test server and client authentication with the Delegated Credential extension with pqtls.
func TestDCPQHandshakeClientAndServerAuth(t *testing.T) {
	clientMsg := "hello, server"
	serverMsg := "hello, client"

	serverConfig := dcTestConfig.Clone()
	serverConfig.ClientAuth = RequestClientCert
	serverConfig.GetCertificate = testServerGetPQCertificate
	clientConfig := dcTestConfig.Clone()
	clientConfig.GetClientCertificate = testClientGetPQCertificate
	clientConfig.PQTLSEnabled = true
	serverConfig.PQTLSEnabled = true
	clientConfig.CurvePreferences = []CurveID{Kyber512}
	serverConfig.CurvePreferences = []CurveID{Kyber512}

	serverConfig.SupportDelegatedCredential = true
	clientConfig.SupportDelegatedCredential = true

	serverConfig.MaxVersion = VersionTLS13
	clientConfig.MaxVersion = VersionTLS13

	initDCTest()

	usedDC, _, usedPQTLS, _, _, err := testConnWithDC(t, clientMsg, serverMsg, clientConfig, serverConfig, "both", false, true)

	if err != nil {
		t.Errorf("test server and client auth with pqs fails: %s", err.Error())
	}

	if usedDC != true {
		t.Errorf("test server and client auth with pqs does not succeed")
	}

	if !usedPQTLS {
		t.Errorf("test server and client auth with pqs did not use pqtls")
	}
}
