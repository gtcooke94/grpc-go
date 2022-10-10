package advancedtls

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"google.golang.org/grpc/security/advancedtls/testdata"
)

func TestCrl(t *testing.T) {
	// revokedLeaf.pem is revoked by 3, 4, 5, 6?
	// *math/big.Int {neg: false, abs: math/big.nat len: 3, cap: 7,
	// [13396399453402159290,11847196829047036697,12920767]}

	// load a CRL
	b, err := ioutil.ReadFile(testdata.Path("crl/6.crl"))
	if err != nil {
		t.Fatalf("ReadFile failed %v", err)
	}
	crl, err := x509.ParseCRL(b)
	// rawIssuer, err := asn1.Marshal(crl.TBSCertList.Issuer.ToRDNSequence())
	if err != nil {
		t.Fatalf("ParseCRL failed %v", err)
	}
	if crl == nil {
		t.Fatalf("crl is nil")
	}
}

func TestCheckRevocation(t *testing.T) {
	dummyCrlFile := []byte(`-----BEGIN X509 CRL-----
MIIDGjCCAgICAQEwDQYJKoZIhvcNAQELBQAwdjELMAkGA1UEBhMCVVMxEzARBgNV
BAgTCkNhbGlmb3JuaWExFDASBgNVBAoTC1Rlc3RpbmcgTHRkMSowKAYDVQQLEyFU
ZXN0aW5nIEx0ZCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkxEDAOBgNVBAMTB1Rlc3Qg
Q0EXDTIxMDExNjAyMjAxNloXDTIxMDEyMDA2MjAxNlowgfIwbAIBAhcNMjEwMTE2
MDIyMDE2WjBYMAoGA1UdFQQDCgEEMEoGA1UdHQEB/wRAMD6kPDA6MQwwCgYDVQQG
EwNVU0ExDTALBgNVBAcTBGhlcmUxCzAJBgNVBAoTAnVzMQ4wDAYDVQQDEwVUZXN0
MTAgAgEDFw0yMTAxMTYwMjIwMTZaMAwwCgYDVR0VBAMKAQEwYAIBBBcNMjEwMTE2
MDIyMDE2WjBMMEoGA1UdHQEB/wRAMD6kPDA6MQwwCgYDVQQGEwNVU0ExDTALBgNV
BAcTBGhlcmUxCzAJBgNVBAoTAnVzMQ4wDAYDVQQDEwVUZXN0MqBjMGEwHwYDVR0j
BBgwFoAURJSDWAOfhGCryBjl8dsQjBitl3swCgYDVR0UBAMCAQEwMgYDVR0cAQH/
BCgwJqAhoB+GHWh0dHA6Ly9jcmxzLnBraS5nb29nL3Rlc3QuY3JshAH/MA0GCSqG
SIb3DQEBCwUAA4IBAQBVXX67mr2wFPmEWCe6mf/wFnPl3xL6zNOl96YJtsd7ulcS
TEbdJpaUnWFQ23+Tpzdj/lI2aQhTg5Lvii3o+D8C5r/Jc5NhSOtVJJDI/IQLh4pG
NgGdljdbJQIT5D2Z71dgbq1ocxn8DefZIJjO3jp8VnAm7AIMX2tLTySzD2MpMeMq
XmcN4lG1e4nx+xjzp7MySYO42NRY3LkphVzJhu3dRBYhBKViRJxw9hLttChitJpF
6Kh6a0QzrEY/QDJGhE1VrAD2c5g/SKnHPDVoCWo4ACIICi76KQQSIWfIdp4W/SY3
qsSIp8gfxSyzkJP+Ngkm2DdLjlJQCZ9R0MZP9Xj4
-----END X509 CRL-----`)
	crl, err := x509.ParseCRL(dummyCrlFile)
	if err != nil {
		t.Fatalf("%v", err)
	}

	crlExt := &certificateListExt{CertList: crl}
	var crlIssuer pkix.Name
	crlIssuer.FillFromRDNSequence(&crl.TBSCertList.Issuer)

	testCert1 := x509.Certificate{
		Issuer: pkix.Name{
			Country:      []string{"USA"},
			Locality:     []string{"here"},
			Organization: []string{"us"},
			CommonName:   "Test1",
		},
		SerialNumber:          big.NewInt(2),
		CRLDistributionPoints: []string{"test"},
	}

	rawIssuer, err := asn1.Marshal(testCert1.Issuer.ToRDNSequence())
	testCert1.RawIssuer = rawIssuer
	rev, err := checkCertRevocation(&testCert1, crlExt)
	if rev == RevocationRevoked {
		t.Errorf("blah")
	}
}

func TestExplore1(t *testing.T) {
	// TODO explore this, caching something, updating the files where it pulls from, etc
	// Maybe make a temp directory in the testing directory and copy files into it, make sure to cleanup
	// Need to have a test that demonstrates behavior that we _don't_ want
	// fetchIssuerCRL()
	// rawIssuer, err := hex.DecodeString("300c310a300806022a030c023a29")
	// if err != nil {
	// 	t.Fatalf("failed to decode issuer: %s", err)
	// }
	// _, err = fetchCRL(rawIssuer, RevocationConfig{RootDir: testdata.Path("crl")})

	var certs = makeChain(t, testdata.Path("crl/revokedInt.pem"))
	rawIssuer := certs[0].RawIssuer
	crl, err := fetchCRL(rawIssuer, RevocationConfig{RootDir: testdata.Path("crl")})
	fmt.Printf("%v, %v", crl, err)
	isRevoked := false
	for _, cert := range certs {
		for _, revoked := range crl.CertList.TBSCertList.RevokedCertificates {
			if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
				isRevoked = true
				continue
			}
		}
	}
	if !isRevoked {
		t.Fatalf("cert wasn't correctly revoked")
	}

	// For full chain need fetchIssuerCrl which also brings in a cert to check
	// But it doesn't fully check the cert, verifyCrl just checks that they are from the same issuer
	// Maybe new function that fetches cached crl
	// cachedCrl kind of does this
}

func TestExplore2(t *testing.T) {
	// revokedInt.pem represents a certificate chain in which the second
	// certificate is revoked in crl3 but not crl4
	// TODO(gregorycooke) loading crl3 vs. crl4 if both are there? One is the root CA, one is the node CA
	cache, err := lru.New(5)
	if err != nil {
		t.Fatalf("Creating lru cache failed")
	}

	// Get cert that we will check
	var certs = makeChain(t, testdata.Path("crl/revokedInt.pem"))
	rawIssuer := certs[0].RawIssuer

	// Pre-load crl4 into the cache. The cert is not revoked in crl4
	// TODO might be cleaner to load in crl3, the remove the revoked cert in it
	crl4 := loadCRL(t, testdata.Path("crl/4.crl"))
	crl4.CertList.TBSCertList.NextUpdate = time.Now().Add(time.Hour)
	// This is gross, we have added crl4 to the cache under the wrong raw issuer
	// for crl4, but it serves the purpose of having an crl in the cache where something is not revoked

	cache.Add(hex.EncodeToString(rawIssuer), crl4)

	// crl, err := fetchIssuerCRL(rawIssuer, certs, RevocationConfig{RootDir: testdata.Path("crl"), Cache: cache})
	for i, cert := range certs {
		revStatus := checkCert(cert, certs, RevocationConfig{RootDir: testdata.Path("crl"), Cache: cache})
		if revStatus != RevocationUnrevoked {
			t.Fatalf("Certificate check should be RevocationUnrevoked, was %v, %v", revStatus, i)
		}
	}

	// With the current implementation, the cache will refresh if NextUpdate has passed
	// Fake that happening (by the time is gets to the code that checks the time, time.Now will have passed)
	crl4.CertList.TBSCertList.NextUpdate = time.Now()
	cache.Add(hex.EncodeToString(rawIssuer), crl4)
	revoked := false
	// crl, err := fetchIssuerCRL(rawIssuer, certs, RevocationConfig{RootDir: testdata.Path("crl"), Cache: cache})
	for _, cert := range certs {
		revStatus := checkCert(cert, certs, RevocationConfig{RootDir: testdata.Path("crl"), Cache: cache})
		if revStatus == RevocationRevoked {
			revoked = true
		}
	}
	if !revoked {
		t.Fatalf("Should've gotten RevocationRevoked, did not")
	}

}

func TestExplore3(t *testing.T) {
	// Get cert that we will check
	// 0, 1 hash to 7a1799af - 3.crl - 1 is revoked (the intermediate cert)
	// 2 hashes to 71eac5a2a - 4.crl - none from this provider are revoked

	var certs = makeChain(t, testdata.Path("crl/revokedInt.pem"))
	for _, cert := range certs {
		raw := cert.RawIssuer
		var r pkix.RDNSequence
		_, err := asn1.Unmarshal(raw, &r)
		if err != nil {
			t.Fatalf("asn1.Unmarshal failed %v", err)
		}
		hash := x509NameHash(r)
		fmt.Println(hash)
	}
}
