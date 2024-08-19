package tls

import (
	"bufio"
	"encoding/csv"
	"errors"
	//"circl/sign"
	"crypto/ecdsa"
	"crypto/elliptic"
	//"crypto/kem"
	"crypto/liboqs_sig"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	//"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	//"regexp"
	"strconv"
	"strings"
	"time"
)

// Command line flags

var (

	// CIRCL Algorithms
	// hsAlgorithms = map[string]CurveID{"Kyber512X25519": Kyber512X25519, "Kyber768X448": Kyber768X448, "Kyber1024X448": Kyber1024X448,
	// 	"SIKEp434X25519": SIKEp434X25519, "SIKEp503X448": SIKEp503X448, "SIKEp751X448": SIKEp751X448}

	// Liboqs Algorithms
	hsKEXAlgorithms = map[string]CurveID{
		"P256": CurveP256, "P384": CurveP384, "P521": CurveP521,
		"Kyber512": OQS_Kyber512, "P256_Kyber512": P256_Kyber512,
		"Kyber768": OQS_Kyber768, "P384_Kyber768": P384_Kyber768,
		"Kyber1024": OQS_Kyber1024, "P521_Kyber1024": P521_Kyber1024,
		"LightSaber_KEM": LightSaber_KEM, "P256_LightSaber_KEM": P256_LightSaber_KEM,
		"Saber_KEM": Saber_KEM, "P384_Saber_KEM": P384_Saber_KEM,
		"FireSaber_KEM": FireSaber_KEM, "P521_FireSaber_KEM": P521_FireSaber_KEM,
		"NTRU_HPS_2048_509": NTRU_HPS_2048_509, "P256_NTRU_HPS_2048_509": P256_NTRU_HPS_2048_509,
		"NTRU_HPS_2048_677": NTRU_HPS_2048_677, "P384_NTRU_HPS_2048_677": P384_NTRU_HPS_2048_677,
		"NTRU_HPS_4096_821": NTRU_HPS_4096_821, "P521_NTRU_HPS_4096_821": P521_NTRU_HPS_4096_821,
		"NTRU_HPS_4096_1229": NTRU_HPS_4096_1229, "P521_NTRU_HPS_4096_1229": P521_NTRU_HPS_4096_1229,
		"NTRU_HRSS_701": NTRU_HRSS_701, "P384_NTRU_HRSS_701": P384_NTRU_HRSS_701,
		"NTRU_HRSS_1373": NTRU_HRSS_1373, "P521_NTRU_HRSS_1373": P521_NTRU_HRSS_1373,
		"P256_Classic-McEliece-348864": P256_Classic_McEliece_348864,
	}

	// Liboqs Algorithms
	hsHybridAuthAlgorithms = map[string]liboqs_sig.ID{
		"P256_Dilithium2": liboqs_sig.P256_Dilithium2, "P256_Falcon512": liboqs_sig.P256_Falcon512,
		"P384_Dilithium3": liboqs_sig.P384_Dilithium3,
		"P521_Dilithium5": liboqs_sig.P521_Dilithium5, "P521_Falcon1024": liboqs_sig.P521_Falcon1024,
	}

	hsClassicAuthAlgorithms = map[string]elliptic.Curve{
		"P256": elliptic.P256(), "P384": elliptic.P384(), "P521": elliptic.P521(),
	}

	// Algorithms to be used in the handshake tests
	testsKEXAlgorithms = []string{
		"Kyber512", "P256_Kyber512", "Kyber768", "P384_Kyber768",
		"Kyber1024", "P521_Kyber1024", "LightSaber_KEM", "P256_LightSaber_KEM",
		"Saber_KEM", "P384_Saber_KEM", "FireSaber_KEM", "P521_FireSaber_KEM",
		"NTRU_HPS_2048_509", "P256_NTRU_HPS_2048_509",
		"NTRU_HPS_2048_677", "P384_NTRU_HPS_2048_677",
		"NTRU_HPS_4096_821", "P521_NTRU_HPS_4096_821",
		"NTRU_HPS_4096_1229", "P521_NTRU_HPS_4096_1229",
		"NTRU_HRSS_701", "P384_NTRU_HRSS_701", "NTRU_HRSS_1373", "P521_NTRU_HRSS_1373",
	}

	testsAuthAlgorithms = []string{
		"P256_Dilithium2", "P256_Falcon512",
		"P384_Dilithium3",
		"P521_Dilithium5", "P521_Falcon1024",
	}

	// Classic algorithms (for both KEX and Auth) to be used in the handshake tests
	testsClassicAlgorithms = []string{
		"P256", "P384", "P521",
	}

	clientHSMsg = "hello, server"
	serverHSMsg = "hello, client"
)

/*func constructHybridRoot(rootFamily string, securityLevel int) (*x509.Certificate, *liboqs_sig.PrivateKey) {

	// ------------------------------ Reading file ------------------------------
	var rootData []string
	var rootFileName string
	var algList []string

	dilithiumAlg := []string{"P256_Dilithium2", "", "P384_Dilithium3", "", "P521_Dilithium5"}
	falconAlg := []string{"P256_Falcon512", "", "P256_Falcon512", "", "P521_Falcon1024"}

	if rootFamily == "dilithium" {
		algList = dilithiumAlg
	} else if rootFamily == "falcon" {
		algList = falconAlg
	} else {
		panic("Unknown Root CA algorithm family")
	}

	if securityLevel == 1 || securityLevel == 3 || securityLevel == 5 {
		rootFileName = "root_ca/hybrid_root_ca_" + algList[securityLevel-1] + ".txt"
	} else {
		panic("Unknown security level")
	}

	file, err := os.Open(rootFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// Resizing scanner's capacity due to P521_RainbowVClassic certificates
	const maxCapacity = 3862673
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		rootData = append(rootData, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	rootSigIDString := rootData[0]

	//curve := rootData[1]
	//curve = curve

	oidBytesString := rootData[2]
	rootPrivClassic := rootData[3]
	rootPrivPqc := rootData[4]
	rootPubClassic := rootData[5]
	rootPubPqc := rootData[6]
	rootCACertString := rootData[7]

	// ---------------------------- Decoding Strings ----------------------------

	rootSigIDInt, err := strconv.ParseUint(rootSigIDString, 16, 16)
	if err != nil {
		panic(err)
	}

	rootSigID := liboqs_sig.ID(rootSigIDInt)

	rootCACertBytes, err := hex.DecodeString(rootCACertString)
	if err != nil {
		panic(err)
	}

	rootCACert, err := x509.ParseCertificate(rootCACertBytes)
	if err != nil {
		panic(err)
	}

	// -------------------------- Classic Priv Parsing --------------------------

	privBytes, err := hex.DecodeString(rootPrivClassic)
	if err != nil {
		panic(err)
	}

	oidBytes, err := hex.DecodeString(oidBytesString)
	if err != nil {
		panic(err)
	}

	namedCurveOID := new(asn1.ObjectIdentifier)
	if _, err := asn1.Unmarshal(oidBytes, namedCurveOID); err != nil {
		panic(err)
	}

	classicPriv, err := x509.ParseECPrivateKeyWithOID(namedCurveOID, privBytes)
	if err != nil {
		panic(err)
	}

	// --------------------------- Classic Pub Parsing --------------------------

	classicPub := new(ecdsa.PublicKey)
	classicPub.Curve, _ = liboqs_sig.ClassicFromSig(rootSigID)

	classicBytes, err := hex.DecodeString(rootPubClassic)
	if err != nil {
		panic(err)
	}

	classicPub.X, classicPub.Y = elliptic.Unmarshal(classicPub.Curve, classicBytes)
	if classicPub.X == nil {
		panic("error in unmarshal ecdsa public key")
	}

	// ------------------ Instantiating Public and Private Key ------------------

	rootPQCPubBytes, err := hex.DecodeString(rootPubPqc)
	if err != nil {
		panic(err)
	}

	rootPQCPrivBytesc, err := hex.DecodeString(rootPrivPqc)
	if err != nil {
		panic(err)
	}

	rootCAPub := liboqs_sig.ConstructPublicKey(rootSigID, classicPub, rootPQCPubBytes)
	rootCAPriv := liboqs_sig.ConstructPrivateKey(rootSigID, classicPriv, rootPQCPrivBytesc, rootCAPub)

	return rootCACert, rootCAPriv
}*/

// Initialize client TLS configuration and certificate chain
/*func initClientAndAuth(k, kAuth string) (*Config, error) {
	var clientConfig *Config

	kexCurveID, err := nameToCurveID(k)
	if err != nil {
		return nil, err
	}

	securityLevelNum := getSecurityLevel(k)

	rootCertX509, intCACert, intCAPriv := constructChain(securityLevelNum)

	if *pqtls || *classic {
		var reLevel1, reLevel3, reLevel5 *regexp.Regexp

		//want same levels for the algos
		reLevel1 = regexp.MustCompile(`P256`)
		reLevel3 = regexp.MustCompile(`P384`)
		reLevel5 = regexp.MustCompile(`P521`)

		securityLevelKauthNum := getSecurityLevel(kAuth)

		// auth in the same level
		if securityLevelNum != securityLevelKauthNum {
			return nil, nil
		}

		//only hybrids
		if !reLevel1.MatchString(k) && !reLevel3.MatchString(k) && !reLevel5.MatchString(k) {
			return nil, nil
		}
		if !reLevel1.MatchString(kAuth) && !reLevel3.MatchString(kAuth) && !reLevel5.MatchString(kAuth) {
			return nil, nil
		}

		authSig := nameToSigID(kAuth)
		clientConfig = initClient(authSig, intCACert, intCAPriv, rootCertX509)
	} else {
		authCurveID, err := nameToCurveID(kAuth)
		if err != nil {
			return nil, err
		}

		clientConfig = initClient(authCurveID, intCACert, intCAPriv, rootCertX509)
	}

	clientConfig.CurvePreferences = []CurveID{kexCurveID}

	return clientConfig, nil
}*/

// Construct Certificate Authority chain (Root CA and Intermediate CA)
func constructChain(rootCertX509 *x509.Certificate, rootPriv *liboqs_sig.PrivateKey) (intCACert *x509.Certificate, intCAPriv interface{}) {

	var intCAAlgo interface{}
	intCAAlgo = rootPriv.SigId

	/*if *hybridRootFamily != "" {
		rootCertX509, rootPriv = constructHybridRoot(*hybridRootFamily, secNum)

		intCAAlgo = rootPriv.(*liboqs_sig.PrivateKey).SigId
	} else {
		tempRootCertTLS, err := LoadX509KeyPair(*rootCert, *rootKey)
		if err != nil {
			panic(err)
		}

		rootCertX509, err = x509.ParseCertificate(tempRootCertCertificate[0])
		if err != nil {
			panic(err)
		}

		rootPriv = tempRootCertPrivateKey

		intCAAlgo = rootPriv.(*ecdsa.PrivateKey).Curve
	}*/

	// intCACert, intCAPriv = initCAs(rootCertX509, rootPriv, intCAAlgo)

	intKeyUsage := x509.KeyUsageCertSign

	intCACertBytes, intCAPriv, err := createCertificate(intCAAlgo, rootCertX509, rootPriv, true, false, "server", intKeyUsage, nil, "localhost", nil)
	if err != nil {
		panic(err)
	}

	intCACert, err = x509.ParseCertificate(intCACertBytes)
	if err != nil {
		panic(err)
	}

	return intCACert, intCAPriv
}

/*func getSecurityLevel(k string) (level int) {
	// want same levels for the algos
	reLevel1 := regexp.MustCompile(`P256`)
	reLevel3 := regexp.MustCompile(`P384`)
	reLevel5 := regexp.MustCompile(`P521`)

	if reLevel1.MatchString(k) || k == "Kyber512" || k == "LightSaber_KEM" || k == "NTRU_HPS_2048_509" {
		return 1
	} else {
		if reLevel3.MatchString(k) || k == "Kyber768" || k == "Saber_KEM" || k == "NTRU_HPS_2048_677" || k == "NTRU_HRSS_701" {
			return 3
		} else {
			if reLevel5.MatchString(k) || k == "Kyber1024" || k == "FireSaber_KEM" || k == "NTRU_HPS_4096_821" || k == "NTRU_HPS_4096_1229" || k == "NTRU_HRSS_1373" {
				return 5
			} else {
				panic("Error when recovering NIST security level number.")
			}
		}
	}
}

func nameToCurveID(name string) (CurveID, error) {
	curveID, prs := hsKEXAlgorithms[name]
	if !prs {
		fmt.Println("Algorithm not found. Available algorithms: ")
		for name, _ := range hsKEXAlgorithms {
			fmt.Println(name)
		}
		return 0, errors.New("ERROR: Algorithm not found")
	}
	return curveID, nil
}

func nameToSigID(name string) interface{} {
	var sigId interface{}
	var prs bool

	if *classic {
		sigId, prs = hsClassicAuthAlgorithms[name]
		if prs {
			return sigId
		}
	} else {
		sigId, prs = hsHybridAuthAlgorithms[name]
		if prs {
			return sigId
		}
	}
	panic("Algorithm not found")
}

func curveIDToName(cID CurveID) (name string, e error) {
	for n, id := range hsKEXAlgorithms {
		if id == cID {
			return n, nil
		}
	}
	return "0", errors.New("ERROR: Algorithm not found")
}

func sigIDToName(sigID interface{}) (name string, e error) {

	if *classic {
		sigEC := sigID.(elliptic.Curve)
		for n, id := range hsClassicAuthAlgorithms {
			if id == sigEC {
				return n, nil
			}
		}
	} else {
		lID := sigID.(liboqs_sig.ID)

		for n, id := range hsHybridAuthAlgorithms {
			if id == lID {
				return n, nil
			}
		}
	}
	return "0", errors.New("ERROR: Auth Algorithm not found")
}*/

// Creates a certificate with the algorithm specified by pubkeyAlgo, signed by signer with signerPrivKey
func createCertificate(pubkeyAlgo interface{}, signer *x509.Certificate, signerPrivKey interface{}, isCA bool, isSelfSigned bool, peer string, keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage, hostName string, mpk []byte) ([]byte, interface{}, error) {

	var _validFor time.Duration

	if isCA {
		_validFor = 8760 * time.Hour // 1 year
	} else {
		_validFor = 240 * time.Hour // 10 days
	}

	var _host string = hostName
	var commonName string

	var pub, priv interface{}
	var err error

	var certDERBytes []byte

	if isCA {
		if isSelfSigned {
			commonName = "Root CA"
		} else {
			commonName = "Intermediate CA"
		}
	} else {
		commonName = peer
	}

	/*if curveID, ok := pubkeyAlgo.(CurveID); ok { // Hybrid KEMTLS
		kemID := kem.ID(curveID)

		pub, priv, err = kem.GenerateKey(rand.Reader, kemID)
		if err != nil {
			return nil, nil, err
		}

	} else if scheme, ok := pubkeyAlgo.(sign.Scheme); ok { // CIRCL Signature
		pub, priv, err = scheme.GenerateKey()

		if err != nil {
			log.Fatalf("Failed to generate private key: %v", err)
		}
	} else*/
	if scheme, ok := pubkeyAlgo.(liboqs_sig.ID); ok { // Liboqs Hybrid Signature
		pub, priv, err = liboqs_sig.GenerateKey(scheme)

		if err != nil {
			log.Fatalf("Failed to generate private key: %v", err)
		}
	} else if scheme, ok := pubkeyAlgo.(elliptic.Curve); ok { // ECDSA

		privECDSA, err := ecdsa.GenerateKey(scheme, rand.Reader)
		if err != nil {
			log.Fatalf("Failed to generate private key: %v", err)
		}

		pub = &privECDSA.PublicKey

		priv = privECDSA
	}

	notBefore := time.Now()

	notAfter := notBefore.Add(_validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	var certTemplate x509.Certificate

	certTemplate = x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
	}

	if mpk != nil {
		certTemplate.ExtraExtensions = append(certTemplate.ExtraExtensions, pkix.Extension{
			Id:    []int{2, 86, 56, 30},
			Value: mpk,
		})
	}

	hosts := strings.Split(_host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			certTemplate.IPAddresses = append(certTemplate.IPAddresses, ip)
		} else {
			certTemplate.DNSNames = append(certTemplate.DNSNames, h)
		}
	}

	if isCA {
		certTemplate.IsCA = true
		certTemplate.KeyUsage |= x509.KeyUsageCertSign
	}

	if isSelfSigned {
		certDERBytes, err = x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, pub, priv)
	} else {
		certDERBytes, err = x509.CreateCertificate(rand.Reader, &certTemplate, signer, pub, signerPrivKey)
	}

	if err != nil {
		return nil, nil, err
	}

	return certDERBytes, priv, nil
}

// Initialize Server's TLS configuration
/*func initServer(certAlgo interface{}, intCACert *x509.Certificate, intCAPriv interface{}, rootCA *x509.Certificate) *Config {
	var err error
	var cfg *Config
	var serverKeyUsage x509.KeyUsage

	cfg = &Config{
		MinVersion:                 VersionTLS10,
		MaxVersion:                 VersionTLS13,
		InsecureSkipVerify:         false,
		SupportDelegatedCredential: false,
	}

	if *pqtls {
		cfg.PQTLSEnabled = true
		serverKeyUsage = x509.KeyUsageDigitalSignature
	} else if *classic {
		serverKeyUsage = x509.KeyUsageDigitalSignature
	} else {
		cfg.KEMTLSEnabled = true
		serverKeyUsage = x509.KeyUsageKeyAgreement
	}

	if *clientAuth {
		cfg.ClientAuth = RequireAndVerifyClientCert
	}

	serverExtKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	certBytes, certPriv, err := createCertificate(certAlgo, intCACert, intCAPriv, false, false, "server", serverKeyUsage, serverExtKeyUsage, *IPserver)
	if err != nil {
		panic(err)
	}

	hybridCert := new(Certificate)

	hybridCert.Certificate = append(hybridCert.Certificate, certBytes)
	hybridCert.PrivateKey = certPriv

	hybridCert.Leaf, err = x509.ParseCertificate(hybridCert.Certificate[0])
	if err != nil {
		panic(err)
	}

	hybridCert.Certificate = append(hybridCert.Certificate, intCACert.Raw)

	cfg.Certificates = make([]Certificate, 1)
	cfg.Certificates[0] = *hybridCert

	if *clientAuth {
		cfg.ClientCAs = x509.NewCertPool()
		cfg.ClientCAs.AddCert(rootCA)
	}

	return cfg
}

// Initializes Client's TLS configuration
func initClient(certAlgo interface{}, intCACert *x509.Certificate, intCAPriv interface{}, rootCA *x509.Certificate) *Config {
	var clientKeyUsage x509.KeyUsage

	ccfg := &Config{
		MinVersion:                 VersionTLS10,
		MaxVersion:                 VersionTLS13,
		InsecureSkipVerify:         false,
		SupportDelegatedCredential: false,
	}

	if *pqtls {
		ccfg.PQTLSEnabled = true
		clientKeyUsage = x509.KeyUsageDigitalSignature
	} else if *classic {
		clientKeyUsage = x509.KeyUsageDigitalSignature
	} else {
		ccfg.KEMTLSEnabled = true
		clientKeyUsage = x509.KeyUsageKeyAgreement
	}

	if *clientAuth {

		hybridCert := new(Certificate)
		var err error

		clientExtKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

		certBytes, certPriv, err := createCertificate(certAlgo, intCACert, intCAPriv, false, false, "client", clientKeyUsage, clientExtKeyUsage, *IPclient)
		if err != nil {
			panic(err)
		}

		hybridCert.Certificate = append(hybridCert.Certificate, certBytes)
		hybridCert.PrivateKey = certPriv
		// hybridCert.SupportedSignatureAlgorithms = []SignatureScheme{Ed25519}

		hybridCert.Leaf, err = x509.ParseCertificate(hybridCert.Certificate[0])
		if err != nil {
			panic(err)
		}

		hybridCert.Certificate = append(hybridCert.Certificate, intCACert.Raw)
		ccfg.Certificates = make([]Certificate, 1)
		ccfg.Certificates[0] = *hybridCert
	}

	ccfg.RootCAs = x509.NewCertPool()

	ccfg.RootCAs.AddCert(rootCA)

	return ccfg
}

/*func newLocalListener(ip string, port string) net.Listener {
	ln, err := net.Listen("tcp", ip+":"+port)
	if err != nil {
		ln, err = net.Listen("tcp6", "[::1]:0")
	}
	if err != nil {
		log.Fatal(err)
	}
	return ln
}*/

type timingInfo struct {
	serverTimingInfo CFEventTLS13ServerHandshakeTimingInfo
	clientTimingInfo CFEventTLS13ClientHandshakeTimingInfo
}

func (ti *timingInfo) eventHandler(event CFEvent) {
	switch e := event.(type) {
	case CFEventTLS13ServerHandshakeTimingInfo:
		ti.serverTimingInfo = e
	case CFEventTLS13ClientHandshakeTimingInfo:
		ti.clientTimingInfo = e
	}
}

// Performs the Test connections in the server side or the client side
/*func testConnHybrid(clientMsg, serverMsg string, tlsConfig *Config, peer string, ipserver string, port string) (timingState timingInfo, cconnState ConnectionState, err error, success bool) {
	tlsConfig.CFEventHandler = timingState.eventHandler

	if peer == "server" {

		handshakeSizes := make(map[string]uint32)

		var timingsFullProtocol []float64
		var timingsWriteServerHello []float64
		var timingsWriteCertVerify []float64
		var timingsReadKEMCiphertext []float64

		buf := make([]byte, len(clientMsg))

		countConnections := 0

		ln := newLocalListener(ipserver, port)
		defer ln.Close()

		ignoreFirstConn := false

		if *cachedCert {
			ignoreFirstConn = true
		}

		for {

			serverConn, err := ln.Accept()
			if err != nil {
				fmt.Print(err)
				fmt.Print("error 1 %v", err)
			}
			server := Server(serverConn, tlsConfig)
			if err := server.Handshake(); err != nil {
				fmt.Printf("Handshake error %v", err)
			}

			//server read client hello
			n, err := server.Read(buf)
			if err != nil || n != len(clientMsg) {
				fmt.Print(err)
				fmt.Print("error 2 %v", err)
			}

			//server responds
			n, err = server.Write([]byte(serverMsg))
			if n != len(serverMsg) || err != nil {
				//error
				fmt.Print(err)
				fmt.Print("error 3 %v", err)
			}

			if ignoreFirstConn {
				ignoreFirstConn = false
				continue
			}

			countConnections++

			cconnState = server.ConnectionState()

			if *pqtls || *classic {

				if (*pqtls && cconnState.DidPQTLS) || *classic {

					if *clientAuth {
						if !cconnState.DidClientAuthentication {
							fmt.Println("Server unsuccessful TLS with mutual authentication")
							continue
						}
					}

					timingsFullProtocol = append(timingsFullProtocol, float64(timingState.serverTimingInfo.FullProtocol)/float64(time.Millisecond))
					timingsWriteServerHello = append(timingsWriteServerHello, float64(timingState.serverTimingInfo.WriteServerHello)/float64(time.Millisecond))
					timingsWriteCertVerify = append(timingsWriteCertVerify, float64(timingState.serverTimingInfo.WriteCertificateVerify)/float64(time.Millisecond))

					if countConnections == *handshakes {
						var kAuth string
						var err error

						kKEX, e := curveIDToName(tlsConfig.CurvePreferences[0])
						if e != nil {
							fmt.Print("4 %v", err)
						}

						if *classic {
							priv, _ := tlsConfig.Certificates[0].PrivateKey.(*ecdsa.PrivateKey)
							kAuth, err = sigIDToName(priv.PublicKey.Curve)
						} else {
							priv, _ := tlsConfig.Certificates[0].PrivateKey.(*liboqs_sig.PrivateKey)
							kAuth, err = sigIDToName(priv.SigId)
						}

						if err != nil {
							fmt.Print("5 %v", err)
						}

						handshakeSizes["ServerHello"] = cconnState.ServerHandshakeSizes.ServerHello
						handshakeSizes["EncryptedExtensions"] = cconnState.ServerHandshakeSizes.EncryptedExtensions
						handshakeSizes["Certificate"] = cconnState.ServerHandshakeSizes.Certificate
						handshakeSizes["CertificateRequest"] = cconnState.ServerHandshakeSizes.CertificateRequest
						handshakeSizes["CertificateVerify"] = cconnState.ServerHandshakeSizes.CertificateVerify
						handshakeSizes["Finished"] = cconnState.ServerHandshakeSizes.Finished

						//kAuth := tlsConfig.Certificates[0].Leaf.PublicKeyAlgorithm.String()
						tlsSaveCSVServer(timingsFullProtocol, timingsWriteServerHello, timingsWriteCertVerify, kKEX, kAuth, countConnections, handshakeSizes)
						countConnections = 0
						timingsFullProtocol = nil
						timingsWriteCertVerify = nil
						timingsWriteServerHello = nil
					}
				} else {
					fmt.Println("Server unsuccessful TLS")
					continue
				}
			} else {
				if cconnState.DidKEMTLS {

					if *clientAuth {
						if !cconnState.DidClientAuthentication {
							fmt.Println("Server unsuccessful KEMTLS with mutual authentication")
							continue
						}
					}

					timingsFullProtocol = append(timingsFullProtocol, float64(timingState.serverTimingInfo.FullProtocol)/float64(time.Millisecond))
					timingsWriteServerHello = append(timingsWriteServerHello, float64(timingState.serverTimingInfo.WriteServerHello)/float64(time.Millisecond))
					timingsReadKEMCiphertext = append(timingsReadKEMCiphertext, float64(timingState.serverTimingInfo.ReadKEMCiphertext)/float64(time.Millisecond))

					if countConnections == *handshakes {
						kKEX, e := curveIDToName(tlsConfig.CurvePreferences[0])
						if e != nil {
							fmt.Print("4 %v", err)
						}

						handshakeSizes["ServerHello"] = cconnState.ServerHandshakeSizes.ServerHello
						handshakeSizes["EncryptedExtensions"] = cconnState.ServerHandshakeSizes.EncryptedExtensions
						handshakeSizes["Certificate"] = cconnState.ServerHandshakeSizes.Certificate
						handshakeSizes["CertificateRequest"] = cconnState.ServerHandshakeSizes.CertificateRequest
						handshakeSizes["ServerKEMCiphertext"] = cconnState.ServerHandshakeSizes.ServerKEMCiphertext
						handshakeSizes["Finished"] = cconnState.ServerHandshakeSizes.Finished

						kemtlsSaveCSVServer(timingsFullProtocol, timingsWriteServerHello, timingsReadKEMCiphertext, kKEX, countConnections, handshakeSizes)
						countConnections = 0
						timingsFullProtocol = nil
						timingsReadKEMCiphertext = nil
						timingsWriteServerHello = nil
					}

				} else {
					fmt.Println("Server unsuccessful KEMTLS")
					continue
				}
			}
		}
	}

	if peer == "client" {

		buf := make([]byte, len(serverMsg))

		client, err := Dial("tcp", ipserver+":"+port, tlsConfig)
		if err != nil {
			fmt.Print(err)
		}
		defer client.Close()

		client.Write([]byte(clientMsg))

		_, err = client.Read(buf)

		cconnState = client.ConnectionState()

		if *pqtls {
			if cconnState.DidPQTLS {

				if *clientAuth {

					if cconnState.DidClientAuthentication {
						log.Println("Client Success using PQTLS with mutual authentication")
					} else {
						log.Println("Client unsuccessful PQTLS with mutual authentication")
						return timingState, cconnState, nil, false
					}

				} else {
					log.Println("Client Success using PQTLS")
				}
			} else {
				log.Println("Client unsuccessful PQTLS")
				return timingState, cconnState, nil, false
			}
		} else if *classic {
			if *clientAuth {
				if cconnState.DidClientAuthentication {
					log.Println("Client Success using TLS with mutual authentication")
				} else {
					log.Println("Client unsuccessful TLS with mutual authentication")
					return timingState, cconnState, nil, false
				}
			} else {
				log.Println("Client Success using TLS")
			}
		} else {
			if cconnState.DidKEMTLS {
				if *clientAuth {

					if cconnState.DidClientAuthentication {
						log.Println("Client Success using KEMTLS with mutual authentication")
					} else {
						log.Println("Client unsuccessful KEMTLS with mutual authentication")
						return timingState, cconnState, nil, false
					}

				} else {
					log.Println("Client Success using KEMTLS")
				}

			} else {
				log.Println("Client unsuccessful KEMTLS")
				return timingState, cconnState, nil, false
			}
		}
	}

	return timingState, cconnState, nil, true
}*/

/*func launchHTTPSServer(serverConfig *Config, port string) {
	http.Handle("/", http.FileServer(http.Dir("./static")))

	addr := ":" + port

	server := &http.Server{
		Addr:      addr,
		Handler:   nil,
		TLSConfig: serverConfig,
	}

	err := server.ListenAndServeTLS("", "")

	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}*/

func constructHybridRoot(rootFileName string) (*x509.Certificate, *liboqs_sig.PrivateKey) {

	/* ------------------------------ Reading file ------------------------------ */
	var rootData []string

	file, err := os.Open(rootFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// Resizing scanner's capacity due to P521_RainbowVClassic certificates
	const maxCapacity = 3862673
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		rootData = append(rootData, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	rootSigIDString := rootData[0]

	oidBytesString := rootData[2]
	rootPrivClassic := rootData[3]
	rootPrivPqc := rootData[4]
	rootPubClassic := rootData[5]
	rootPubPqc := rootData[6]
	rootCACertString := rootData[7]

	/* ---------------------------- Decoding Strings ---------------------------- */

	rootSigIDInt, err := strconv.ParseUint(rootSigIDString, 16, 16)
	if err != nil {
		panic(err)
	}

	rootSigID := liboqs_sig.ID(rootSigIDInt)

	rootCACertBytes, err := hex.DecodeString(rootCACertString)
	if err != nil {
		panic(err)
	}

	rootCACert, err := x509.ParseCertificate(rootCACertBytes)
	if err != nil {
		panic(err)
	}

	/* -------------------------- Classic Priv Parsing -------------------------- */

	privBytes, err := hex.DecodeString(rootPrivClassic)
	if err != nil {
		panic(err)
	}

	oidBytes, err := hex.DecodeString(oidBytesString)
	if err != nil {
		panic(err)
	}

	namedCurveOID := new(asn1.ObjectIdentifier)
	if _, err := asn1.Unmarshal(oidBytes, namedCurveOID); err != nil {
		panic(err)
	}

	classicPriv, err := x509.ParseECPrivateKeyWithOID(namedCurveOID, privBytes)
	if err != nil {
		panic(err)
	}

	/* --------------------------- Classic Pub Parsing -------------------------- */

	classicPub := new(ecdsa.PublicKey)
	classicPub.Curve, _ = liboqs_sig.ClassicFromSig(rootSigID)

	classicBytes, err := hex.DecodeString(rootPubClassic)
	if err != nil {
		panic(err)
	}

	classicPub.X, classicPub.Y = elliptic.Unmarshal(classicPub.Curve, classicBytes)
	if classicPub.X == nil {
		panic("error in unmarshal ecdsa public key")
	}

	/* ------------------ Instantiating Public and Private Key ------------------ */

	rootPQCPubBytes, err := hex.DecodeString(rootPubPqc)
	if err != nil {
		panic(err)
	}

	rootPQCPrivBytesc, err := hex.DecodeString(rootPrivPqc)
	if err != nil {
		panic(err)
	}

	rootCAPub := liboqs_sig.ConstructPublicKey(rootSigID, classicPub, rootPQCPubBytes)
	rootCAPriv := liboqs_sig.ConstructPrivateKey(rootSigID, classicPriv, rootPQCPrivBytesc, rootCAPub)

	return rootCACert, rootCAPriv
}

func generateHybridRoot(rootCAAlgo interface{}, curve elliptic.Curve) {
	rootKeyUsage := x509.KeyUsageCertSign
	rootCACertBytes, rootCAPriv, err := createCertificate(rootCAAlgo, nil, nil, true, true, "server", rootKeyUsage, nil, "localhost", nil)
	if err != nil {
		panic(err)
	}
	priv, ok := rootCAPriv.(*liboqs_sig.PrivateKey)
	if !ok {
		panic("Aqui")
	}
	oid, ok := x509.OidFromNamedCurve(curve)
	if !ok {
		panic("x509: unknown curve while marshaling to PKCS#8")
	}
	oidBytes, err := asn1.Marshal(oid)
	if err != nil {
		panic("x509: failed to marshal curve OID: " + err.Error())
	}
	var curveString string
	switch curve {
	case elliptic.P256():
		curveString = "P256"
	case elliptic.P384():
		curveString = "P384"
	case elliptic.P521():
		curveString = "P521"
	}
	privClassic, privPqc, pub := liboqs_sig.GetPrivateKeyMembers(priv)
	pubClassic, pubPqc := liboqs_sig.GetPublicKeyMembers(pub)
	rootPrivBytes, err := x509.MarshalECPrivateKey(privClassic)
	if err != nil {
		panic("x509: failed to marshal EC private key while building PKCS#8: " + err.Error())
	}
	classicPubBytes := elliptic.Marshal(pubClassic.Curve, pubClassic.X, pubClassic.Y)
	sigIDString := strconv.FormatInt(int64(priv.SigId), 16)

	rootCAData := []string{sigIDString, curveString, hex.EncodeToString(oidBytes), hex.EncodeToString(rootPrivBytes), hex.EncodeToString(privPqc), hex.EncodeToString(classicPubBytes), hex.EncodeToString(pubPqc), hex.EncodeToString(rootCACertBytes)}
	fileName := "hybrid_root_ca.txt"
	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}

	datawriter := bufio.NewWriter(file)

	for _, data := range rootCAData {
		_, _ = datawriter.WriteString(data + "\n")
	}

	datawriter.Flush()
	file.Close()
}

func tlsInitCSV() {
	if _, err := os.Stat("csv/tls-client.csv"); errors.Is(err, os.ErrNotExist) {
		csvFile, err := os.Create("csv/tls-client.csv")
		if err != nil {
			log.Fatalf("failed creating file: %s", err)
		}
		csvwriter := csv.NewWriter(csvFile)
		header := []string{"algo",
			"timingFullProtocol",
			"timingProcessServerHello",
			"timingWriteClientHello"}
		csvwriter.Write(header)
		csvwriter.Flush()
		csvFile.Close()
	}
}

func tlsServerInitCSV() {
	if _, err := os.Stat("csv/tls-server.csv"); errors.Is(err, os.ErrNotExist) {
		csvFile, err := os.Create("csv/tls-server.csv")
		if err != nil {
			log.Fatalf("failed creating file: %s", err)
		}
		csvwriter := csv.NewWriter(csvFile)
		header := []string{"algo",
			"timingFullProtocol",
			"timingWriteServerHello",
			"timingWriteCertVerify"}
		csvwriter.Write(header)
		csvwriter.Flush()
		csvFile.Close()
	}
}

func kemtlsInitCSV() {
	if _, err := os.Stat("csv/kemtls-client.csv"); errors.Is(err, os.ErrNotExist) {
		csvFile, err := os.Create("csv/kemtls-client.csv")
		if err != nil {
			log.Fatalf("failed creating file: %s", err)
		}
		csvwriter := csv.NewWriter(csvFile)

		header := []string{"algo", "timingFullProtocol", "timingSendAppData", "timingProcessServerHello", "timingWriteClientHello", "timingWriteKEMCiphertext"}

		csvwriter.Write(header)
		csvwriter.Flush()
		csvFile.Close()
	}
	if _, err := os.Stat("csv/kemtls-client-sizes.csv"); errors.Is(err, os.ErrNotExist) {
		csvFile, err := os.Create("csv/kemtls-client-sizes.csv")
		if err != nil {
			log.Fatalf("failed creating file: %s", err)
		}
		csvwriter := csv.NewWriter(csvFile)

		header := []string{"Algo", "ClientHello", "ClientKEMCiphertext", "Certificate", "Finished", "Total"}

		csvwriter.Write(header)
		csvwriter.Flush()
		csvFile.Close()
	}
}

func kemtlsInitCSVServer() {
	if _, err := os.Stat("csv/kemtls-server.csv"); errors.Is(err, os.ErrNotExist) {
		csvFile, err := os.Create("csv/kemtls-server.csv")
		if err != nil {
			log.Fatalf("failed creating file: %s", err)
		}
		csvwriter := csv.NewWriter(csvFile)

		header := []string{"algo", "timingFullProtocol", "timingWriteServerHello", "timingReadKEMCiphertext"}

		csvwriter.Write(header)
		csvwriter.Flush()
		csvFile.Close()
	}
	if _, err := os.Stat("csv/kemtls-server-sizes.csv"); errors.Is(err, os.ErrNotExist) {
		csvFile, err := os.Create("csv/kemtls-server-sizes.csv")
		if err != nil {
			log.Fatalf("failed creating file: %s", err)
		}
		csvwriter := csv.NewWriter(csvFile)

		header := []string{"algo", "ServerHello", "EncryptedExtensions", "Certificate", "CertificateRequest", "ServerKEMCiphertext", "Finished", "Total"}

		csvwriter.Write(header)
		csvwriter.Flush()
		csvFile.Close()
	}
}

func tlsServerSaveCSV(name string, timingsFullProtocol float64, timingsWriteServerHello float64, timingsWriteCertVerify float64) {
	csvFile, err := os.OpenFile("csv/tls-server.csv", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}
	csvwriter := csv.NewWriter(csvFile)

	arrayStr := []string{
		name,
		fmt.Sprintf("%f", timingsFullProtocol),
		fmt.Sprintf("%f", timingsWriteServerHello),
		fmt.Sprintf("%f", timingsWriteCertVerify)}

	if err := csvwriter.Write(arrayStr); err != nil {
		log.Fatalln("error writing record to file", err)
	}
	csvwriter.Flush()

	csvFile.Close()
}

func tlsSaveCSV(name string, timingsFullProtocol float64, timingsProcessServerHello float64, timingsWriteClientHello float64) {
	csvFile, err := os.OpenFile("csv/tls-client.csv", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}
	csvwriter := csv.NewWriter(csvFile)

	arrayStr := []string{
		name,
		fmt.Sprintf("%f", timingsFullProtocol),
		fmt.Sprintf("%f", timingsProcessServerHello),
		fmt.Sprintf("%f", timingsWriteClientHello)}

	if err := csvwriter.Write(arrayStr); err != nil {
		log.Fatalln("error writing record to file", err)
	}
	csvwriter.Flush()

	csvFile.Close()
}

func kemtlsSaveCSV(name string, timingsFullProtocol float64, timingsSendAppData float64, timingsProcessServerHello float64, timingsWriteClientHello float64, timingsWriteKEMCiphertext float64, sizes map[string]uint32) {
	csvFile, err := os.OpenFile("csv/kemtls-client.csv", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}

	csvwriter := csv.NewWriter(csvFile)

	arrayStr := []string{
		name,
		fmt.Sprintf("%f", timingsFullProtocol),
		fmt.Sprintf("%f", timingsSendAppData),
		fmt.Sprintf("%f", timingsProcessServerHello),
		fmt.Sprintf("%f", timingsWriteClientHello),
		fmt.Sprintf("%f", timingsProcessServerHello)}

	if err := csvwriter.Write(arrayStr); err != nil {
		log.Fatalln("error writing record to file", err)
	}
	csvwriter.Flush()

	csvFile.Close()

	csvFile, err = os.OpenFile("csv/kemtls-client-sizes.csv", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}

	csvwriter = csv.NewWriter(csvFile)

	totalSizes := sizes["ClientHello"] + sizes["ClientKEMCiphertext"] + sizes["ClientCertificate"] + sizes["Finished"]

	arrayStr = []string{name,
		fmt.Sprintf("%d", sizes["ClientHello"]),
		fmt.Sprintf("%d", sizes["ClientKEMCiphertext"]),
		fmt.Sprintf("%d", sizes["ClientCertificate"]),
		fmt.Sprintf("%d", sizes["Finished"]),
		fmt.Sprintf("%d", totalSizes),
	}

	if err := csvwriter.Write(arrayStr); err != nil {
		log.Fatalln("error writing record to file", err)
	}
	csvwriter.Flush()
	csvFile.Close()

}

func kemtlsSaveCSVServer(name string, timingsFullProtocol float64, timingsWriteServerHello float64, timingsReadKEMCiphertext float64, sizes map[string]uint32) {
	csvFile, err := os.OpenFile("csv/kemtls-server.csv", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}

	csvwriter := csv.NewWriter(csvFile)

	arrayStr := []string{
		name,
		fmt.Sprintf("%f", timingsFullProtocol),
		fmt.Sprintf("%f", timingsWriteServerHello),
		fmt.Sprintf("%f", timingsReadKEMCiphertext)}

	if err := csvwriter.Write(arrayStr); err != nil {
		log.Fatalln("error writing record to file", err)
	}
	csvwriter.Flush()

	csvFile.Close()

	csvFile, err = os.OpenFile("csv/kemtls-server-sizes.csv", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}

	csvwriter = csv.NewWriter(csvFile)

	totalSizes := sizes["ServerHello"] + sizes["EncryptedExtensions"] + sizes["Certificate"] + sizes["CertificateRequest"] + sizes["ServerKEMCiphertext"] + sizes["Finished"]

	arrayStr = []string{name,
		fmt.Sprintf("%d", sizes["ServerHello"]),
		fmt.Sprintf("%d", sizes["EncryptedExtensions"]),
		fmt.Sprintf("%d", sizes["Certificate"]),
		fmt.Sprintf("%d", sizes["CertificateRequest"]),
		fmt.Sprintf("%d", sizes["ServerKEMCiphertext"]),
		fmt.Sprintf("%d", sizes["Finished"]),
		fmt.Sprintf("%d", totalSizes),
	}

	if err := csvwriter.Write(arrayStr); err != nil {
		log.Fatalln("error writing record to file", err)
	}
	csvwriter.Flush()
	csvFile.Close()
}
