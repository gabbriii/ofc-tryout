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
	"os"
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

var ca *x509.Certificate
var caPK *rsa.PrivateKey

func Handle(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		io.WriteString(w, "This service only accepts POST method")
	} else {
		// get our CA cert and priv key
		err := certSetup()
		if err != nil {
			io.WriteString(w, err.Error())
		}

		// sign a CSR
		s, err := certSigning(w, req)
		if err != nil {
			io.WriteString(w, err.Error())
		}
		io.WriteString(w, "THIS IS A DEMO\n")
		io.WriteString(w, "Here is your TLS certificate signed:\n")
		io.WriteString(w, s)
	}
}

func certSetup() (err error) {
	caCert, err := os.ReadFile("./static/rootCACert.pem")
	if err != nil {
		return err
	}
	caKey, err := os.ReadFile("./static/rootCAKey.pem")
	if err != nil {
		return err
	}
	pemBlock, _ := pem.Decode(caCert)
	if pemBlock == nil {
		panic("pem.Decode CA failed")
	}
	pemBlock2, _ := pem.Decode(caKey)
	if pemBlock2 == nil {
		panic("pem.Decode CA_KEY failed")
	}
	ca, err = x509.ParseCertificate(pemBlock.Bytes) //pemBlock.Bytes
	if err != nil {
		return err
	}
	caPK, err = x509.ParsePKCS1PrivateKey(pemBlock2.Bytes) //pemBlock2.Bytes
	if err != nil {
		return err
	}
	return
}

func certSigning(w http.ResponseWriter, req *http.Request) (s string, err error) {
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
	PK := getPK([]byte(CSR.PublicKey), n)

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

	// generating a fake private key
	fakePrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	fakePrivKey.PublicKey.N = PK.N
	fakePrivKey.PublicKey.E = PK.E

	// signing
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

func getPK(b []byte, CSR int) (PK PublicKey) {
	n := new(big.Int)
	PK.N = n.SetBytes(b)
	PK.E = CSR
	return
}
