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

//var ca_str string = "-----BEGIN CERTIFICATE-----\nMIIDuzCCAqOgAwIBAgIUaWynyktJM5J4b+QVfwBzzDMmhZEwDQYJKoZIhvcNAQEL\nBQAwbTELMAkGA1UEBhMCRVMxEzARBgNVBAgMClNvbWUtU3RhdGUxEjAQBgNVBAcM\nCUJhcmNlbG9uYTEWMBQGA1UECgwNRW50cnVzdChmYWtlKTELMAkGA1UECwwCSVQx\nEDAOBgNVBAMMB0dhYnJpZWwwHhcNMjIwNTE3MDgyMjE4WhcNMzIwNTE0MDgyMjE4\nWjBtMQswCQYDVQQGEwJFUzETMBEGA1UECAwKU29tZS1TdGF0ZTESMBAGA1UEBwwJ\nQmFyY2Vsb25hMRYwFAYDVQQKDA1FbnRydXN0KGZha2UpMQswCQYDVQQLDAJJVDEQ\nMA4GA1UEAwwHR2FicmllbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\nALREdvN0jaKoO8s0w0UqrXu3UbLllSlr5ZsCW/afrutGy8Z94ebRdEdPsMCidIer\niw4ph7Fel2aSzVEGOPSiqbKcxEtOS4hDTFrBvjLb8zezINW3b//p+KUXohwmN009\nQST/+z1U9fVewQOYOnj0inMfKKbUM+kk9vGUk7VSwwS7qfRHmeZYpQRKc929BdKE\nWcTN5NSJtdT5hpxR3p5YX92fjNDEvZAIzBYLtcOXooJpe6lw9HAXX42hMB1TR2uz\nZXiUTBS8c1r+h0Q0f4ItnhfzAX3nZQDFfcI3Ozc3va13tRKQaDD7vck6rzcZgtoC\niiTld9fECvLL9PwmJGW1Os8CAwEAAaNTMFEwHQYDVR0OBBYEFL6Gh7k4KhR3yTIW\n/DQfKMh2KimIMB8GA1UdIwQYMBaAFL6Gh7k4KhR3yTIW/DQfKMh2KimIMA8GA1Ud\nEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAA0R12nXS0LtYkK+iKTxRMzP\npLMSYd4+esmUZruQ5PFUaVpth4ajYRr4BQ5/gWwxqzEQmSHnvvfilJSxQAEi4agk\nZgZQlvetjzTWRbap7Y83iMrgxJ80PpuH68V0E0LobMIFCXz7X10OrnOgV3KFRnFY\nJ6kVQWfXqxorSGcbTAKSUd8xtayeXX40GC8mngh1901dE2qfdjIbccvcWDy9BMMn\nXekGV+FRNK2RCDUw3G/ovfGnNl/zwJ8vAE9AKSxPaLdlbJtR+/EPmLSwgTqTuKLq\nI+8mSUEnkJE3bVxVywuTD6cpawD/bjwm7bf0NKJ/khcGIkYuGwUVcvAhl1Ax7AI=\n-----END CERTIFICATE-----"
//var ca_key_str string = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEAtER283SNoqg7yzTDRSqte7dRsuWVKWvlmwJb9p+u60bLxn3h\n5tF0R0+wwKJ0h6uLDimHsV6XZpLNUQY49KKpspzES05LiENMWsG+MtvzN7Mg1bdv\n/+n4pReiHCY3TT1BJP/7PVT19V7BA5g6ePSKcx8optQz6ST28ZSTtVLDBLup9EeZ\n5lilBEpz3b0F0oRZxM3k1Im11PmGnFHenlhf3Z+M0MS9kAjMFgu1w5eigml7qXD0\ncBdfjaEwHVNHa7NleJRMFLxzWv6HRDR/gi2eF/MBfedlAMV9wjc7Nze9rXe1EpBo\nMPu9yTqvNxmC2gKKJOV318QK8sv0/CYkZbU6zwIDAQABAoIBAQCcxvKA13wa259t\nIk01iWFpuExIfxzT8m+0+T9L5SK2olK1JWPjX4R2RJtfXaplF88PGRVXMAIShlgk\nQHomYJWfrnGVYNmV/5mXUOp+xwXnClXjKO8yLaU+x6gIPUBZX42ZhTtW4t4qcScC\nXlF0QpFqf83WEbW37ZsLDYHM79aF9M58vMencdT5pKLpv3lyH5zpZr/vPz+vpGvR\nX4aKhEscRvyWVYeAwwFg3HQ6OvsWIWfx7BfpJqkhuz91M4+hoxJcIqqQMaB/L09g\nLHnWxfC7TI+btji4gLGsCuvocIbo5M2AOPkBxvQb48ON9JzAF6e874sAKkzeHgH7\npEeoQ6epAoGBAN5/tvmR8cbu2sZ6DK7x6AYTrDPsUguoBals4ka3l3eQVAQmKr10\n9tUehn1EZjjfG0piF+iqmeLoqhQDr9kWHMWv+FzHWVarsQGsZbg0FdheRRx+Ke81\nLABGHsAYmiiU8pYedz/spZsWWhbzIHKSL86D3UUsDJEiW0dr9MfFGlYDAoGBAM9o\n7SYRCDwmnQQhn0Q1St6bvYMMnGdzbXx+dQq5uQ20TCCZBX2pz6XJ61e8hL7wdkvj\nn6ladwpVuaOECoY6YDyttINvl+I3Opeg6Hlhquthc75ztwbDV6dMBnq33eqkj4fF\nTLD6sKp/tgy1PzQg1d+LbB2GuUEaZaxmyzcxbARFAoGAPBabsKzEceght0ZQ1JJK\nChIYCHHC+pjm5omcVmLQih61QeWY10+WNZon0f696JAAS8dQE6q3InuZKwyP2f3J\nyW2rkkrYCrsVc5E+a0/NsoBLA9Xit1JRzsUhGtnKEDmhhf82T1I2qzqPG/GPCsIG\nHSypfjvWLP/tTM2P7r+BTEcCgYEAsGRUC2PA1SchsjnF8YRBQEDDU4iOG40XOCFz\n+MMqlnUXqUF6YfzhE+Y9uEgjvR9T/AaB6s19H9T4JBBPwwgygGhadM2bJlBCDGJU\nU6a0bapbfUV8Csxm52jIueVVXhDF4HnzVzBcvyQN95DNR9AFFDDGqfXB55RDk/N4\nMGBftOECgYEAloI1nJXRsIgsLarRkONECo9utUbpVffpTPYjVqizcU8IKVH7OMzv\na/Cbp304sQrMGnvQceWAY4jeomIwVGTW5a8AF451GNZ7CpjNEKcLMnTE8rCXLKWI\nlcJ18D9gFzHEFfwNbCfG0AUSzfHywmcN4QxU/Zvdf/GTuO955kVTFho=\n-----END RSA PRIVATE KEY-----"

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
		io.WriteString(w, "Here is your TLS certificate signed:\n")
		io.WriteString(w, s)
	}
}

func certSetup() (err error) {
	//var CA []byte = []byte(ca_str)
	//var CA_KEY []byte = []byte(ca_key_str)

	caCert, err := os.ReadFile("./static/rootCACert.pem")
	if err != nil {
		panic("caCert")
		//return err
	}
	caKey, err := os.ReadFile("./static/rootCAKey.pem")
	if err != nil {
		panic("caKey")
		//return err
	}

	/*pemBlock, _ := pem.Decode(CA)
	if pemBlock == nil {
		panic("pem.Decode CA failed")
	}
	pemBlock2, _ := pem.Decode(CA_KEY)
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
	}*/
	ca, err = x509.ParseCertificate(caCert) //pemBlock.Bytes
	if err != nil {
		panic("caCertPem")
		//return err
	}
	caPK, err = x509.ParsePKCS1PrivateKey(caKey) //pemBlock2.Bytes
	if err != nil {
		panic("caKeyPem")
		//return err
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
