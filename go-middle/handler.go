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

func Handle(w http.ResponseWriter, req *http.Request) {
	// get our CA cert and priv key
	ca, caPK, err := certsetup()
	if err != nil {
		panic(err)
	}

	if req.Method == "GET" {
		io.WriteString(w, "This service only accepts POST method")
	} else {
		io.WriteString(w, "Hello, TLS!\n")
		s, _ := certsigning(w, req, ca, caPK)
		/*if err != nil {
			panic(err)
		}*/
		io.WriteString(w, s)
	}
}

func certsetup() (ca *x509.Certificate, caPK *rsa.PrivateKey, err error) {
	/*_, err = os.Stat("./server.pem")
	_, er := os.Stat("./server_key.pem")
	if err == nil && er == nil {
		// retrieve CA cert and key
		CRTfile, err := os.ReadFile("./server.pem")
		if err != nil {
			return nil, nil, err
		}
		KEYfile, err := os.ReadFile("./server_key.pem")
		if err != nil {
			return nil, nil, err
		}
		pemBlock, _ := pem.Decode(CRTfile)
		if pemBlock == nil {
			panic("pem.Decode failed")
		}
		pemBlock2, _ := pem.Decode(KEYfile)
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
	} else {*/
	// set up our CA
	ca = &x509.Certificate{
		SerialNumber: big.NewInt(2021),
		Subject: pkix.Name{
			Organization:  []string{"Entrust(fake)"},
			Country:       []string{"ES"},
			Province:      []string{""},
			Locality:      []string{"Barcelona"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
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

	// create the CA
	//caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	//if err != nil {
	//	return nil, nil, err
	//}

	//NEW START
	// create our CA cert
	/*cert := &x509.Certificate{
		SerialNumber: big.NewInt(2021),
		Subject: pkix.Name{
			Organization:  []string{"Entrust-IT automation"},
			Country:       []string{"ES"},
			Province:      []string{""},
			Locality:      []string{"Barcelona"},
			StreetAddress: []string{"WTC"},
			PostalCode:    []string{"94016"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPK)
	if err != nil {
		return nil, nil, err
	}

	//START
	serverCERTfile, err := os.Create("server.pem")
	if err != nil {
		return nil, nil, err
	}
	pem.Encode(serverCERTfile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	serverCERTfile.Close()
	//END

	//START
	serverKEYfile, err := os.Create("server_key.pem")
	if err != nil {
		return nil, nil, err
	}
	pem.Encode(serverKEYfile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey)})
	serverKEYfile.Close()*/
	//END
	//NEW END

	return
}

func certsigning(w http.ResponseWriter, req *http.Request, ca *x509.Certificate, caPK *rsa.PrivateKey) (s string, err error) {
	req.Body = http.MaxBytesReader(w, req.Body, 1048576)
	dec := json.NewDecoder(req.Body)
	var CSR csr
	err = dec.Decode(&CSR)
	if err != nil {
		return "decode fail", err
	}

	n, err := strconv.Atoi(CSR.Exponent)
	if err != nil {
		return "atoi fail", err
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
		return "fakePK fail", err
	}
	fakePrivKey.PublicKey.N = PK.N
	fakePrivKey.PublicKey.E = PK.E

	clientcertBytes, err := x509.CreateCertificate(rand.Reader, &clientcertTemplate, ca, &fakePrivKey.PublicKey, caPK)
	if err != nil {
		return "signing fail", err
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
