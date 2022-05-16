package function

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"time"
)

type subject struct {
	Country  string `json:"country,omitempty"`
	Locality string `json:"locality,omitempty"`
	Org      string `json:"org,omitempty"`
	Orgunit  string `json:"orgunit,omitempty"`
	Comname  string `json:"comname,omitempty"`
	Email    string `json:"email,omitempty"`
}

type csr struct {
	Signature          string  `json:"signature,omitempty"`
	SignatureAlgorithm string  `json:"signaturealgorithm,omitempty"`
	PublicKeyAlgorithm string  `json:"publickeyalgorithm,omitempty"`
	PublicKey          string  `json:"publickey,omitempty"`
	Exponent           string  `json:"exponent,omitempty"`
	Subject            subject `json:"subject,omitempty"`
}

type PublicKey struct {
	N *big.Int // modulus
	E int      // public exponent
}

type cert struct {
	CRT string `json:"crt,omitempty"`
}

var ca_str string = "MIIFfTCCA2WgAwIBAgIUT163/9oviMKBegmzh32VEB4fgL8wDQYJKoZIhvcNAQEL\nBQAwTjELMAkGA1UEBhMCRVMxEzARBgNVBAgMClNvbWUtU3RhdGUxEjAQBgNVBAcM\nCUJhcmNlbG9uYTEWMBQGA1UECgwNRW50cnVzdChmYWtlKTAeFw0yMjA0MjgwOTU2\nNDNaFw0yNzA0MjcwOTU2NDNaME4xCzAJBgNVBAYTAkVTMRMwEQYDVQQIDApTb21l\nLVN0YXRlMRIwEAYDVQQHDAlCYXJjZWxvbmExFjAUBgNVBAoMDUVudHJ1c3QoZmFr\nZSkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDhDH1Nae/dpC8wl11A\nFZvq24RZ5jnXrecAbt83mgkwulNJYmcPTukcTv5rjEjugBdsk4OMn9YpRSgLB9x2\nNCThLvNjOev77hFSWN1Csy8HsR3MUqPTnTgBmxOTeM5kvCJlQx0MirHPxxdOEpSI\nhW4PXiAOB7XbZXUWHgK1hb2qTLy2aH7oet0ftSx9YiWDxmoz5bcrbzkE7iJezVq5\nPmKizNiQZJnEpU53V/DfTBw10gOTawAtQyCipiZl1QC47Pr4Eu7cG26uymv+xTM4\nZ3pQ3T9IslOsgKVsoIDUrMIjkT3moPOZgYNMUSbHS/IuyZQtCurarM/dxtvPSknz\nUHodNIumm3WKPhBjPHvu+tJmOCaW4AuKGwgGPYcM9ZytVJqTGGzC/FSRVrjiRBoV\nHAUbwHUD5p8o4hdtTV/abMy32kIpWGRlqx6s9FvSNMEnQIZP5SSaw0CqyjL5UCjc\nwnt62K2u/9G4Exx7OArzmaNGKWfls+rfE92aKMjXbSdPe/2puF4XjcZYDM8z4HKR\nZbNcR0/LH3lBoZWvX9a6Qn3M6f8yL8Xd8eTxf2qIU/wv3DaurDC5KPaBY6qZRIIQ\nDRJWjJZxeZvIrdeuSPAQsdEYjz6QAX/41DEzAHAvLu32STFgWjk8XpO9r5NCRMJN\ntonV19gjBL8cU41JAGBPkUhbfQIDAQABo1MwUTAdBgNVHQ4EFgQU7w1jmbeHCMAT\ngoj2V7cPB480eQkwHwYDVR0jBBgwFoAU7w1jmbeHCMATgoj2V7cPB480eQkwDwYD\nVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEARiF85cblzn6sWaqN6EOv\nzM/tN5Z7q5CP31Lg1eHF6EGakT2yTzHPDAkjPp63smxWsSz8Y+6+reLD8Jj5MYsS\nPzxRfVo57f1aXyvX/gigWd8hk60TcwzQ0U1mSuYGed4GjkR0YIn+RqMNtj/XRViO\n/UjcuxQPVcYkV7IyCxsphznEFgOCfwSnzRcJ8+rt+hzwuqVNQCKuYbMlLsdNFsnZ\n2p3rH51CFkBBbu1OD116s0DjsVeZNJYJoOHu4YvBJuB3XQPZdxBkjtoZNMFkVti4\nznVp2kwamtlx3BTSkJExUzYxWFXOorgsUa8DOEKT+spQNl/9zr9ytVpNOEsmYHvj\nOUwNmOHaV+RrJiGRvZaDzn7s77SoKnSIff1Vet3QANoXuSGGWOESO/ih2q39QmIm\n31DHxv5+qMhbtC6OYwDwWsN7q5gLldyLBUK4szeDlrHT1Rr8KU0t0hGhEyoqCa2L\n+W++3lWMGQ349Sghw74fh4MCgYjTgyMVKBMSRVyNmPy2YLgv+elbDugZKStmAueq\nVkGcdrKxnb/B0/M1vdfy9BHkMaEkKfgq/zODncY2+7Sna/E8iC0inmlINZx8ay9U\nrPDnJCt1Mq9E6xvRi36600T0OA8DfUz9+7bSQZRvdU42ZxYdtVqj+6mgru4F2Edq\nUmo5dp5Cbn5WNTfhPXwIzg0="

var ca_key_str = "Proc-Type: 4,ENCRYPTED\nDEK-Info: DES-EDE3-CBC,6CB3B34F1192FAF1\n\n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"

func Handle(w http.ResponseWriter, req *http.Request) {
	// get our CA cert and priv key
	ca, caPK, err := certsetup()
	if err != nil {
		io.WriteString(w, err.Error())
	}

	if req.Method == "GET" {
		io.WriteString(w, "This service only accepts POST method")
	} else {
		s, err := certsigning(w, req, ca, caPK)
		if err != nil {
			io.WriteString(w, err.Error())
		}
		io.WriteString(w, "Here is your TLS certificate signed:\n")
		io.WriteString(w, s)
	}
}

func certsetup() (ca *x509.Certificate, caPK *rsa.PrivateKey, err error) {
	//new begin
	/*CA, ca_existance := os.LookupEnv("CA")
	CA_KEY, ca_key_existance := os.LookupEnv("CA_KEY")
	if !ca_existance || !ca_key_existance {
		panic("CA or CA_key not found")
	}*/
	CA := []byte(ca_str)
	CA_KEY := []byte(ca_key_str)
	pemBlock, _ := pem.Decode(CA)
	if pemBlock == nil {
		panic("pem.Decode failed")
	}
	pemBlock2, _ := pem.Decode(CA_KEY)
	if pemBlock2 == nil {
		panic("pem.Decode failed")
	}
	ca, err = x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	caPK, err = x509.ParsePKCS1PrivateKey(pemBlock2.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return

	// set up our CA
	/*ca = &x509.Certificate{
		SerialNumber: big.NewInt(2021),
		Subject: pkix.Name{
			Organization:  []string{"Entrust(fake)"},
			Country:       []string{"ES"},
			Province:      []string{"Catalunya"},
			Locality:      []string{"Barcelona"},
			StreetAddress: []string{"Moll de Barcelona"},
			PostalCode:    []string{"s/n"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caPK, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	return*/
}

func certsigning(w http.ResponseWriter, req *http.Request, ca *x509.Certificate, caPK *rsa.PrivateKey) (s string, err error) {
	req.Body = http.MaxBytesReader(w, req.Body, 1048576)
	dec := json.NewDecoder(req.Body)
	var CSR csr
	err = dec.Decode(&CSR)
	if err != nil {
		return "", err
	}
	n, err := strconv.Atoi(CSR.Exponent)
	if err != nil {
		return "", err
	}
	PK := get_PK([]byte(CSR.PublicKey), n)

	clientcertTemplate := x509.Certificate{
		Signature:          []byte(CSR.Signature),
		SignatureAlgorithm: 4, //hardcoded, future imp

		PublicKeyAlgorithm: 1, //hardcoded, future imp
		PublicKey:          PK,

		SerialNumber: big.NewInt(2),
		Issuer:       ca.Subject,
		Subject: pkix.Name{
			Organization:       []string{CSR.Subject.Org},
			Country:            []string{CSR.Subject.Country},
			Locality:           []string{CSR.Subject.Locality},
			OrganizationalUnit: []string{CSR.Subject.Orgunit},
			CommonName:         CSR.Subject.Comname,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	fakePrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", err
	}
	fakePrivKey.PublicKey.N = PK.N
	fakePrivKey.PublicKey.E = PK.E

	clientcertBytes, err := x509.CreateCertificate(rand.Reader, &clientcertTemplate, ca, &fakePrivKey.PublicKey, caPK)
	if err != nil {
		return "", err
	}
	clientcertPEM := new(bytes.Buffer)
	pem.Encode(clientcertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientcertBytes,
	})

	s = clientcertPEM.String()
	return
}

func get_PK(b []byte, CSR int) (PK PublicKey) {
	n := new(big.Int)
	PK.N = n.SetBytes(b)
	PK.E = CSR
	return
}
