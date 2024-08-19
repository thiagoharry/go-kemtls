package tls

import (
	"crypto/elliptic"
	//"crypto/liboqs_sig" // When generating new hybrid certs
	"crypto/liboqs_sig"
	"crypto/x509"
	"fmt"
	"gitlab.labsec.ufsc.br/equipe-icp/pqc/go-ibe-pqc/pkg/combiner/xorMac"
	dlp "gitlab.labsec.ufsc.br/equipe-icp/pqc/go-ibe-pqc/pkg/idkem/dlp2"
	"gitlab.labsec.ufsc.br/equipe-icp/pqc/go-ibe-pqc/pkg/kem/ec"
	"os"
	"sync"
	"testing"
	"time"
)

var (
	ibeTestConfig    *Config
	ibeTestKEMScheme = []SignatureScheme{KEMTLSWithP256_Kyber512}
	intCACert        *x509.Certificate
	intCAPriv        interface{}
	hybridCert       Certificate
	wg               sync.WaitGroup
)

var hybridIBEServerTests = []struct {
	clientDCSupport bool
	clientMaxVers   uint16
	serverMaxVers   uint16
	expectSuccess   bool
	expectDC        bool
	name            string
}{
	{false, VersionTLS13, VersionTLS13, true, false, "Hybrid IBE Test"},
}

func init() {
	cert, _ := os.ReadFile("root_cert.der")
	rootCert, _ := x509.ParseCertificate(cert)
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(rootCert)
	// You can run this only once to generate the hybrid root:
	//generateHybridRoot(liboqs_sig.P384_Dilithium3, elliptic.P384())
	ibeTestConfig = &Config{
		//Time: func() time.Time {
		//	return time.Date(2023, time.September, 29, 06, 0, 0, 234234, time.UTC)
		//},
		Rand:                   zeroSource{},
		Certificates:           nil,
		MinVersion:             VersionTLS13,
		MaxVersion:             VersionTLS13,
		CipherSuites:           allCipherSuites(),
		HybridIBEKEMTLSEnabled: true,
		KEMTLSEnabled:          true,
		RootCAs:                rootCAs,
	}
	testConfig = &Config{
		Rand:         zeroSource{},
		Certificates: nil,
		CipherSuites: allCipherSuites(),
		RootCAs:      rootCAs,
		MinVersion:   VersionTLS13,
		MaxVersion:   VersionTLS13,
		Time:         time.Now,
	}
}

func initHybridCert(conf *Config) {
	// Root certificate
	hybridRootCert, hybridRootPriv := constructHybridRoot("dilithium3_p384_root_ca.txt")
	conf.RootCAs.AddCert(hybridRootCert)
	// Intermediate certificate
	intCACertBytes, intCAPriv, err := createCertificate(liboqs_sig.P384_Dilithium3, hybridRootCert, hybridRootPriv, true, false, "server", x509.KeyUsageCertSign, nil, "127.0.0.1", nil)
	if err != nil {
		panic(err)
	}
	intCACert, err = x509.ParseCertificate(intCACertBytes)
	if err != nil {
		panic(err)
	}
	//  Leaf certificate
	certBytes, certPriv, err := createCertificate(elliptic.P256(), intCACert, intCAPriv, false, false, "server", x509.KeyUsageKeyAgreement, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, "localhost", nil)
	if err != nil {
		panic(err)
	}
	hybridCert.Certificate = append(hybridCert.Certificate, certBytes)
	hybridCert.PrivateKey = certPriv
	hybridCert.Leaf, err = x509.ParseCertificate(hybridCert.Certificate[0])
	if err != nil {
		panic(err)
	}
	hybridCert.Certificate = append(hybridCert.Certificate, intCACert.Raw)
	conf.Certificates = make([]Certificate, 1)
	conf.Time = time.Now
}

func initHybridCertMpk(conf *Config) {
	// Root certificate
	hybridRootCert, hybridRootPriv := constructHybridRoot("dilithium3_p384_root_ca.txt")
	//intKeyUsage := x509.KeyUsageCertSign
	conf.RootCAs.AddCert(hybridRootCert)
	// Intermediate certificate
	intCACertBytes, intCAPriv, err := createCertificate(liboqs_sig.P384_Dilithium3, hybridRootCert, hybridRootPriv, true, false, "server", x509.KeyUsageCertSign, nil, "127.0.0.1", nil)
	if err != nil {
		panic(err)
	}
	intCACert, err = x509.ParseCertificate(intCACertBytes)
	if err != nil {
		panic(err)
	}
	//  Leaf certificate
	combiner := new(xormac.Combiner)
	scheme, err := combiner.NewScheme(new(ec.Scheme), new(dlp.Scheme))
	if err != nil {
		panic(err)
	}
	kdc, err := scheme.KeyGen(128)
	if err != nil {
		panic(err)
	}
	mpk, err := kdc.MasterPublic()
	if err != nil {
		panic(err)
	}
	certBytes, certPriv, err := createCertificate(elliptic.P256(), intCACert, intCAPriv, false, false, "server", x509.KeyUsageKeyAgreement, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, "localhost", mpk) // IBE MPK
	if err != nil {
		panic(err)
	}
	hybridCert.Certificate = append(hybridCert.Certificate, certBytes)
	hybridCert.PrivateKey = certPriv
	hybridCert.Leaf, err = x509.ParseCertificate(hybridCert.Certificate[0])
	if err != nil {
		panic(err)
	}
	hybridCert.Certificate = append(hybridCert.Certificate, intCACert.Raw)
	conf.Certificates = make([]Certificate, 1)
	conf.Time = time.Now
}

func testServerHybridIBECertificate(ch *ClientHelloInfo) (*Certificate, error) {
	cert, err := LoadX509KeyPair("ibe_cert.pem", "ibe_key.pem")
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func testServerHybridIBEHybridCertificate(ch *ClientHelloInfo) (*Certificate, error) {
	return &hybridCert, nil
}

func TestLoadingHybridAlgorithms(t *testing.T) {
	var combiner = new(xormac.Combiner)
	var idScheme = new(dlp.Scheme)
	var pkiScheme = new(ec.Scheme)
	_, err := combiner.NewScheme(pkiScheme, idScheme)
	if err != nil {
		t.Error("Error generating hybrid KEM.")
	}
}

func TestClientTLS13(t *testing.T) {
	var timingStateClient timingInfo
	serverMsg := "hello, client"
	clientMsg := "hello, server"
	clientConfig := testConfig.Clone()
	clientConfig.Time = time.Now
	clientConfig.CurvePreferences = []CurveID{CurveP256}
	clientConfig.CFEventHandler = timingStateClient.eventHandler
	clientConfig.ServerName = "localhost"
	serverAddress := os.Getenv("TLSSERVER")
	if serverAddress == "" {
		serverAddress = "localhost"
	}
	tlsInitCSV()
	_, _, _, _, err :=
		testClientConnWithDC(t, clientMsg, serverAddress+":4432",
			clientConfig, serverMsg, true, false)
	if err != nil {
		t.Errorf("test with kem #%d fails: %s",
			dcCount, err.Error())
	} else {
		timingsFullProtocolClient := float64(timingStateClient.clientTimingInfo.FullProtocol) / float64(time.Millisecond)
		timingsProcessServerHello := float64(timingStateClient.clientTimingInfo.ProcessServerHello) / float64(time.Millisecond)
		timingsWriteClientHello := float64(timingStateClient.clientTimingInfo.WriteClientHello) / float64(time.Millisecond)
		tlsSaveCSV("P256", timingsFullProtocolClient,
			timingsProcessServerHello, timingsWriteClientHello)
	}
}

func TestServerTLS13(t *testing.T) {
	var timingStateServer timingInfo
	serverMsg := "hello, client"
	clientMsg := "hello, server"
	serverConfig := testConfig.Clone()
	serverConfig.Time = time.Now
	serverConfig.CurvePreferences = []CurveID{CurveP256}
	serverConfig.CFEventHandler = timingStateServer.eventHandler
	serverConfig.ServerName = "localhost"
	serverConfig.GetCertificate = testServerHybridIBECertificate
	serverAddress := os.Getenv("TLSSERVER")
	if serverAddress == "" {
		serverAddress = "localhost"
	}
	tlsServerInitCSV()
	_, _, _, _, err :=
		testServerConnWithDC(t, clientMsg, serverMsg, ":4432",
			serverConfig, true, false)
	if err != nil {
		t.Errorf("test with kem #%d fails: %s",
			dcCount, err.Error())
	} else {
		timingsFullProtocol := float64(timingStateServer.serverTimingInfo.FullProtocol) / float64(time.Millisecond)
		timingsWriteServerHello := float64(timingStateServer.serverTimingInfo.WriteServerHello) / float64(time.Millisecond)
		timingsWriteCertVerify := float64(timingStateServer.serverTimingInfo.WriteCertificateVerify) / float64(time.Millisecond)
		tlsServerSaveCSV("P256", timingsFullProtocol, timingsWriteServerHello,
			timingsWriteCertVerify)
	}
}

func TestClientKEMTLSIBE1(t *testing.T) {
	var timingStateClient timingInfo
	serverMsg := "hello, client"
	clientMsg := "hello, server"
	clientConfig := ibeTestConfig.Clone()
	clientConfig.KEMTLSEnabled = true
	clientConfig.CFEventHandler = timingStateClient.eventHandler
	clientConfig.CurvePreferences = []CurveID{P256_Kyber512}
	combiner := new(xormac.Combiner)
	clientConfig.ServerName = "localhost"
	serverAddress := os.Getenv("TLSSERVER")
	if serverAddress == "" {
		serverAddress = "localhost"
	}
	scheme, err := combiner.NewScheme(new(ec.Scheme), new(dlp.Scheme))
	if err != nil {
		t.Error(err)
	}
	kdc, err := scheme.KeyGen(128)
	if err != nil {
		t.Error(err)
	}
	clientConfig.Mpk, err = kdc.MasterPublic()
	if err != nil {
		t.Error(err)
	}
	kemtlsInitCSV()
	for i, test := range hybridIBEServerTests {
		clientConfig.SupportDelegatedCredential = test.clientDCSupport
		for dcCount = 0; dcCount < len(ibeTestKEMScheme); dcCount++ {
			initDCTest()
			clientConfig.MaxVersion = test.clientMaxVers
			_, _, _, clientState, err :=
				testClientConnWithDC(t, clientMsg, serverAddress+":4433",
					clientConfig, serverMsg, true, false)
			if err != nil {
				t.Errorf("test #%d (%s) with kem #%d fails: %s",
					i, test.name, dcCount, err.Error())
				os.Exit(1)
			} else {
				timingsFullProtocolClient := float64(timingStateClient.clientTimingInfo.FullProtocol) / float64(time.Millisecond)
				timingsSendAppData := float64(timingStateClient.clientTimingInfo.SendAppData) / float64(time.Millisecond)
				timingsProcessServerHello := float64(timingStateClient.clientTimingInfo.ProcessServerHello) / float64(time.Millisecond)
				timingsWriteClientHello := float64(timingStateClient.clientTimingInfo.WriteClientHello) / float64(time.Millisecond)
				timingsWriteKEMCiphertext := float64(timingStateClient.clientTimingInfo.WriteKEMCiphertext) / float64(time.Millisecond)
				handshakeSizes := make(map[string]uint32)
				handshakeSizes["ClientHello"] = clientState.ClientHandshakeSizes.ClientHello
				handshakeSizes["ClientKEMCiphertext"] = clientState.ClientHandshakeSizes.ClientKEMCiphertext
				handshakeSizes["ClientCertificate"] = clientState.ClientHandshakeSizes.Certificate
				handshakeSizes["Finished"] = clientState.ClientHandshakeSizes.Finished
				kemtlsSaveCSV("Remote IBE-KEM 128", timingsFullProtocolClient, timingsSendAppData, timingsProcessServerHello, timingsWriteClientHello, timingsWriteKEMCiphertext, handshakeSizes)
			}
			// Preparing pre-distributed key test
			clientConfig.CachedCert = clientState.CertificateMessage
			clientConfig.CachedCertReq = clientState.CertificateReqMessage
			time.Sleep(2 * time.Second)
			_, _, _, _, err =
				testClientConnWithDC(t, clientMsg, serverAddress+":8080",
					clientConfig, "hello, client",
					true, false)
			if err != nil {
				t.Errorf("test #%d (%s) with kem #%d fails: %s",
					i, test.name, dcCount, err.Error())
				os.Exit(1)
			} else {
				timingsFullProtocolClient := float64(timingStateClient.clientTimingInfo.FullProtocol) / float64(time.Millisecond)
				timingsSendAppData := float64(timingStateClient.clientTimingInfo.SendAppData) / float64(time.Millisecond)
				timingsProcessServerHello := float64(timingStateClient.clientTimingInfo.ProcessServerHello) / float64(time.Millisecond)
				timingsWriteClientHello := float64(timingStateClient.clientTimingInfo.WriteClientHello) / float64(time.Millisecond)
				timingsWriteKEMCiphertext := float64(timingStateClient.clientTimingInfo.WriteKEMCiphertext) / float64(time.Millisecond)
				handshakeSizes := make(map[string]uint32)
				handshakeSizes["ClientHello"] = clientState.ClientHandshakeSizes.ClientHello
				handshakeSizes["ClientKEMCiphertext"] = clientState.ClientHandshakeSizes.ClientKEMCiphertext
				handshakeSizes["ClientCertificate"] = clientState.ClientHandshakeSizes.Certificate
				handshakeSizes["Finished"] = clientState.ClientHandshakeSizes.Finished
				kemtlsSaveCSV("Remote PDK IBE-KEM 128", timingsFullProtocolClient, timingsSendAppData, timingsProcessServerHello, timingsWriteClientHello, timingsWriteKEMCiphertext, handshakeSizes)
			}
		}
	}

}

func TestServerKEMTLSIBE1(t *testing.T) {
	var timingStateServer timingInfo
	serverMsg := "hello, client"
	clientMsg := "hello, server"
	serverConfig := ibeTestConfig.Clone()
	serverConfig.CFEventHandler = timingStateServer.eventHandler

	serverConfig.KEMTLSEnabled = true
	serverConfig.CurvePreferences = []CurveID{P256_Kyber512}
	combiner := new(xormac.Combiner)
	serverConfig.ServerName = "localhost"
	scheme, err := combiner.NewScheme(new(ec.Scheme), new(dlp.Scheme))
	if err != nil {
		t.Error(err)
	}
	kdc, err := scheme.KeyGen(128)
	if err != nil {
		t.Error(err)
	}
	serverConfig.SkID, err = kdc.Extract(serverConfig.ServerName)
	if err != nil {
		t.Error(err)
	}
	serverConfig.Mpk, err = kdc.MasterPublic()
	if err != nil {
		t.Error(err)
	}
	kemtlsInitCSVServer()
	for i, test := range hybridIBEServerTests {
		for dcCount = 0; dcCount < len(ibeTestKEMScheme); dcCount++ {
			initDCTest()
			serverConfig.GetCertificate = testServerHybridIBECertificate
			serverConfig.MaxVersion = test.serverMaxVers
			_, _, _, serverState, err :=
				testServerConnWithDC(t, clientMsg, serverMsg, ":4433",
					serverConfig, true, false)
			if err != nil {
				t.Errorf("test #%d (%s) with kem #%d fails: %s",
					i, test.name, dcCount, err.Error())
				os.Exit(1)
			}
			handshakeSizes := make(map[string]uint32)
			timingsFullProtocolServer := float64(timingStateServer.serverTimingInfo.FullProtocol) / float64(time.Millisecond)
			timingsWriteServerHello := float64(timingStateServer.serverTimingInfo.WriteServerHello) / float64(time.Millisecond)
			timingsReadKEMCiphertext := float64(timingStateServer.serverTimingInfo.ReadKEMCiphertext) / float64(time.Millisecond)
			handshakeSizes["ServerHello"] = serverState.ServerHandshakeSizes.ServerHello
			handshakeSizes["EncryptedExtensions"] = serverState.ServerHandshakeSizes.EncryptedExtensions
			handshakeSizes["Certificate"] = serverState.ServerHandshakeSizes.Certificate
			handshakeSizes["CertificateRequest"] = serverState.ServerHandshakeSizes.CertificateRequest
			handshakeSizes["CertificateVerify"] = serverState.ServerHandshakeSizes.CertificateVerify
			handshakeSizes["Finished"] = serverState.ServerHandshakeSizes.Finished
			kemtlsSaveCSVServer("Remote IBE-KEM 128", timingsFullProtocolServer, timingsWriteServerHello, timingsReadKEMCiphertext, handshakeSizes)
			// Preparing pre-distributed key test
			serverConfig.CachedCert = serverState.CertificateMessage
			serverConfig.CachedCertReq = serverState.CertificateReqMessage
			_, _, _, _, err =
				testServerConnWithDC(t, clientMsg, serverMsg, ":8080",
					serverConfig, true, false)
			if err != nil {
				t.Errorf("test #%d (%s) with kem #%d fails: %s",
					i, test.name, dcCount, err.Error())
				os.Exit(1)
			}
			handshakeSizes = make(map[string]uint32)
			timingsFullProtocolServer = float64(timingStateServer.serverTimingInfo.FullProtocol) / float64(time.Millisecond)
			timingsWriteServerHello = float64(timingStateServer.serverTimingInfo.WriteServerHello) / float64(time.Millisecond)
			timingsReadKEMCiphertext = float64(timingStateServer.serverTimingInfo.ReadKEMCiphertext) / float64(time.Millisecond)
			handshakeSizes["ServerHello"] = serverState.ServerHandshakeSizes.ServerHello
			handshakeSizes["EncryptedExtensions"] = serverState.ServerHandshakeSizes.EncryptedExtensions
			handshakeSizes["Certificate"] = serverState.ServerHandshakeSizes.Certificate
			handshakeSizes["CertificateRequest"] = serverState.ServerHandshakeSizes.CertificateRequest
			handshakeSizes["CertificateVerify"] = serverState.ServerHandshakeSizes.CertificateVerify
			handshakeSizes["Finished"] = serverState.ServerHandshakeSizes.Finished
			kemtlsSaveCSVServer("Remote PDK IBE-KEM 128", timingsFullProtocolServer, timingsWriteServerHello, timingsReadKEMCiphertext, handshakeSizes)

		}
	}
}

func TestServerMpk1(t *testing.T) {
	var timingStateServer timingInfo
	serverMsg := "hello, client"
	clientMsg := "hello, server"
	serverConfig := ibeTestConfig.Clone()
	serverConfig.CFEventHandler = timingStateServer.eventHandler
	serverConfig.MpkExtension = true
	serverConfig.KEMTLSEnabled = true
	serverConfig.CurvePreferences = []CurveID{P256_Kyber512}
	combiner := new(xormac.Combiner)
	serverConfig.ServerName = "localhost"
	scheme, err := combiner.NewScheme(new(ec.Scheme), new(dlp.Scheme))
	if err != nil {
		t.Error(err)
	}
	kdc, err := scheme.KeyGen(128)
	if err != nil {
		t.Error(err)
	}
	serverConfig.SkID, err = kdc.Extract(serverConfig.ServerName)
	if err != nil {
		t.Error(err)
	}
	serverConfig.Mpk, err = kdc.MasterPublic()
	if err != nil {
		t.Error(err)
	}
	serverConfig.GetCertificate = testServerHybridIBECertificate
	kemtlsInitCSVServer()
	wg.Add(1)
	go testConnHybrid(clientMsg, serverMsg, serverConfig, "server", "", "4436")
	wg.Wait()
}

func TestClientMpk1(t *testing.T) {
	var timingStateClient timingInfo
	serverMsg := "hello, client"
	clientMsg := "hello, server"
	clientConfig := ibeTestConfig.Clone()
	clientConfig.KEMTLSEnabled = true
	clientConfig.CFEventHandler = timingStateClient.eventHandler
	clientConfig.CurvePreferences = []CurveID{P256_Kyber512}
	combiner := new(xormac.Combiner)
	clientConfig.ServerName = "localhost"
	clientConfig.MpkExtension = true
	serverAddress := os.Getenv("TLSSERVER")
	if serverAddress == "" {
		serverAddress = "localhost"
	}
	scheme, err := combiner.NewScheme(new(ec.Scheme), new(dlp.Scheme))
	if err != nil {
		t.Error(err)
	}
	kdc, err := scheme.KeyGen(128)
	if err != nil {
		t.Error(err)
	}
	clientConfig.Mpk, err = kdc.MasterPublic()
	if err != nil {
		t.Error(err)
	}
	kemtlsInitCSV()
	for i, test := range hybridIBEServerTests {
		clientConfig.SupportDelegatedCredential = test.clientDCSupport
		for dcCount = 0; dcCount < len(ibeTestKEMScheme); dcCount++ {
			initDCTest()
			clientConfig.MaxVersion = test.clientMaxVers
			_, _, _, clientState, err :=
				testClientConnWithDC(t, clientMsg, serverAddress+":4436",
					clientConfig, serverMsg, true, false)
			if err != nil {
				t.Errorf("test #%d (%s) with kem #%d fails: %s",
					i, test.name, dcCount, err.Error())
				os.Exit(1)
			} else {
				timingsFullProtocolClient := float64(timingStateClient.clientTimingInfo.FullProtocol) / float64(time.Millisecond)
				timingsSendAppData := float64(timingStateClient.clientTimingInfo.SendAppData) / float64(time.Millisecond)
				timingsProcessServerHello := float64(timingStateClient.clientTimingInfo.ProcessServerHello) / float64(time.Millisecond)
				timingsWriteClientHello := float64(timingStateClient.clientTimingInfo.WriteClientHello) / float64(time.Millisecond)
				timingsWriteKEMCiphertext := float64(timingStateClient.clientTimingInfo.WriteKEMCiphertext) / float64(time.Millisecond)
				handshakeSizes := make(map[string]uint32)
				handshakeSizes["ClientHello"] = clientState.ClientHandshakeSizes.ClientHello
				handshakeSizes["ClientKEMCiphertext"] = clientState.ClientHandshakeSizes.ClientKEMCiphertext
				handshakeSizes["ClientCertificate"] = clientState.ClientHandshakeSizes.Certificate
				handshakeSizes["Finished"] = clientState.ClientHandshakeSizes.Finished
				kemtlsSaveCSV("Remote IBE-KEM-MPK 128", timingsFullProtocolClient, timingsSendAppData, timingsProcessServerHello, timingsWriteClientHello, timingsWriteKEMCiphertext, handshakeSizes)
			}
		}
	}

}

func TestClientKEMTLSIBE2(t *testing.T) {
	var timingStateClient timingInfo
	initHybridCert(ibeTestConfig)
	clientMsg := "hello, server"
	serverMsg := "hello, client"
	clientConfig := ibeTestConfig.Clone()
	clientConfig.Certificates = nil
	clientConfig.KEMTLSEnabled = true
	clientConfig.CurvePreferences = []CurveID{P384_Kyber768}
	//clientConfig.InsecureSkipVerify = true
	combiner := new(xormac.Combiner)
	clientConfig.ServerName = "localhost"
	clientConfig.CFEventHandler = timingStateClient.eventHandler
	serverAddress := os.Getenv("TLSSERVER")
	if serverAddress == "" {
		serverAddress = "localhost"
	}
	scheme, err := combiner.NewScheme(new(ec.Scheme), new(dlp.Scheme))
	if err != nil {
		t.Error(err)
	}
	kdc, err := scheme.KeyGen(192)
	if err != nil {
		t.Error(err)
	}
	clientConfig.Mpk, err = kdc.MasterPublic()
	if err != nil {
		t.Error(err)
	}
	kemtlsInitCSV()

	buf := make([]byte, len(serverMsg))
	client, err := Dial("tcp", serverAddress+":4434", clientConfig)
	if err != nil {
		fmt.Printf("CONN FAIL: %v\n", err)
		t.Error("")
	}
	defer client.Close()
	client.Write([]byte(clientMsg))
	_, err = client.Read(buf)
	clientState := client.ConnectionState()
	if !clientState.DidKEMTLS {
		fmt.Printf("IBE KEMTLS FAILED\n")
		t.Error("")
	}
	clientConfig.CachedCert = clientState.CertificateMessage
	clientConfig.CachedCertReq = clientState.CertificateReqMessage
	client, err = Dial("tcp", serverAddress+":4434", clientConfig)
	if err != nil {
		fmt.Printf("CONN FAIL: %v\n", err)
		t.Error("")
	}
	defer client.Close()
	client.Write([]byte(clientMsg))
	_, err = client.Read(buf)
	clientState = client.ConnectionState()
	if clientState.DidKEMTLS {
		timingsFullProtocolClient := float64(timingStateClient.clientTimingInfo.FullProtocol) / float64(time.Millisecond)
		timingsSendAppData := float64(timingStateClient.clientTimingInfo.SendAppData) / float64(time.Millisecond)
		timingsProcessServerHello := float64(timingStateClient.clientTimingInfo.ProcessServerHello) / float64(time.Millisecond)
		timingsWriteClientHello := float64(timingStateClient.clientTimingInfo.WriteClientHello) / float64(time.Millisecond)
		timingsWriteKEMCiphertext := float64(timingStateClient.clientTimingInfo.WriteKEMCiphertext) / float64(time.Millisecond)
		handshakeSizes := make(map[string]uint32)
		handshakeSizes["ClientHello"] = clientState.ClientHandshakeSizes.ClientHello
		handshakeSizes["ClientKEMCiphertext"] = clientState.ClientHandshakeSizes.ClientKEMCiphertext
		handshakeSizes["ClientCertificate"] = clientState.ClientHandshakeSizes.Certificate
		handshakeSizes["Finished"] = clientState.ClientHandshakeSizes.Finished
		kemtlsSaveCSV("KEMTLS-IBE-PDK 384", timingsFullProtocolClient, timingsSendAppData, timingsProcessServerHello, timingsWriteClientHello, timingsWriteKEMCiphertext, handshakeSizes)
	} else {
		fmt.Printf("IBE KEMTLS FAILED\n")
		t.Error("")
	}

}

func TestServerKEMTLSIBE2(t *testing.T) {
	var timingStateServer timingInfo
	initHybridCert(ibeTestConfig)
	serverMsg := "hello, client"
	clientMsg := "hello, server"
	serverConfig := ibeTestConfig.Clone()
	serverConfig.KEMTLSEnabled = true
	serverConfig.CurvePreferences = []CurveID{P384_Kyber768}
	serverConfig.CFEventHandler = timingStateServer.eventHandler
	//clientConfig.InsecureSkipVerify = true
	combiner := new(xormac.Combiner)
	serverConfig.ServerName = "localhost"
	serverConfig.Certificates = make([]Certificate, 1)
	serverConfig.Certificates[0] = hybridCert
	scheme, err := combiner.NewScheme(new(ec.Scheme), new(dlp.Scheme))
	if err != nil {
		t.Error(err)
	}
	kdc, err := scheme.KeyGen(192)
	if err != nil {
		t.Error(err)
	}
	serverConfig.SkID, err = kdc.Extract(serverConfig.ServerName)
	if err != nil {
		t.Error(err)
	}
	serverConfig.Mpk, err = kdc.MasterPublic()
	if err != nil {
		t.Error(err)
	}
	kemtlsInitCSVServer()

	wg.Add(1)
	go testConnHybrid(clientMsg, serverMsg, serverConfig, "server", "", "4434")
	wg.Wait()
}

func TestServerMpk2(t *testing.T) {
	var timingStateServer timingInfo
	initHybridCertMpk(ibeTestConfig)
	clientMsg := "hello, server"
	serverMsg := "hello, client"
	serverConfig := ibeTestConfig.Clone()
	serverConfig.KEMTLSEnabled = true
	serverConfig.CurvePreferences = []CurveID{P384_Kyber768}
	serverConfig.CFEventHandler = timingStateServer.eventHandler
	//clientConfig.InsecureSkipVerify = true
	combiner := new(xormac.Combiner)
	serverConfig.ServerName = "localhost"
	serverConfig.Certificates = make([]Certificate, 1)
	serverConfig.Certificates[0] = hybridCert
	scheme, err := combiner.NewScheme(new(ec.Scheme), new(dlp.Scheme))
	if err != nil {
		t.Error(err)
	}
	kdc, err := scheme.KeyGen(192)
	if err != nil {
		t.Error(err)
	}
	serverConfig.SkID, err = kdc.Extract(serverConfig.ServerName)
	if err != nil {
		t.Error(err)
	}
	serverConfig.Mpk, err = kdc.MasterPublic()
	if err != nil {
		t.Error(err)
	}
	kemtlsInitCSVServer()
	wg.Add(1)
	go testConnHybrid(clientMsg, serverMsg, serverConfig, "server", "", "4435")
	wg.Wait()
}

func TestClientMpk2(t *testing.T) {
	var timingStateClient timingInfo
	initHybridCert(ibeTestConfig)
	clientMsg := "hello, server"
	serverMsg := "hello, client"
	clientConfig := ibeTestConfig.Clone()
	clientConfig.Certificates = nil
	clientConfig.KEMTLSEnabled = true
	clientConfig.CurvePreferences = []CurveID{P384_Kyber768}
	combiner := new(xormac.Combiner)
	clientConfig.ServerName = "localhost"
	clientConfig.CFEventHandler = timingStateClient.eventHandler
	serverAddress := os.Getenv("TLSSERVER")
	if serverAddress == "" {
		serverAddress = "localhost"
	}
	scheme, err := combiner.NewScheme(new(ec.Scheme), new(dlp.Scheme))
	if err != nil {
		t.Error(err)
	}
	kdc, err := scheme.KeyGen(192)
	if err != nil {
		t.Error(err)
	}
	clientConfig.Mpk, err = kdc.MasterPublic()
	if err != nil {
		t.Error(err)
	}
	kemtlsInitCSV()

	buf := make([]byte, len(serverMsg))
	client, err := Dial("tcp", serverAddress+":4435", clientConfig)
	if err != nil {
		fmt.Printf("CONN FAIL: %v\n", err)
		t.Error("")
	}
	defer client.Close()
	client.Write([]byte(clientMsg))
	_, err = client.Read(buf)
	clientState := client.ConnectionState()
	if !clientState.DidKEMTLS {
		fmt.Printf("IBE KEMTLS FAILED\n")
		t.Error("")
	} else {
		timingsFullProtocolClient := float64(timingStateClient.clientTimingInfo.FullProtocol) / float64(time.Millisecond)
		timingsSendAppData := float64(timingStateClient.clientTimingInfo.SendAppData) / float64(time.Millisecond)
		timingsProcessServerHello := float64(timingStateClient.clientTimingInfo.ProcessServerHello) / float64(time.Millisecond)
		timingsWriteClientHello := float64(timingStateClient.clientTimingInfo.WriteClientHello) / float64(time.Millisecond)
		timingsWriteKEMCiphertext := float64(timingStateClient.clientTimingInfo.WriteKEMCiphertext) / float64(time.Millisecond)
		handshakeSizes := make(map[string]uint32)
		handshakeSizes["ClientHello"] = clientState.ClientHandshakeSizes.ClientHello
		handshakeSizes["ClientKEMCiphertext"] = clientState.ClientHandshakeSizes.ClientKEMCiphertext
		handshakeSizes["ClientCertificate"] = clientState.ClientHandshakeSizes.Certificate
		handshakeSizes["Finished"] = clientState.ClientHandshakeSizes.Finished
		kemtlsSaveCSV("KEMTLS-IBE-MPK 384", timingsFullProtocolClient, timingsSendAppData, timingsProcessServerHello, timingsWriteClientHello, timingsWriteKEMCiphertext, handshakeSizes)
	}
}
