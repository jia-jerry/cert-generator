package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

func decodePrivateKey(bytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(bytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("could not decode the PEM-encoded RSA private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
func decodeCertificate(bytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(bytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("could not decode the PEM-encoded certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func encodeCertificate(certificate []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate,
	})
}
func encodePrivateKey(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func signCertificate(certificateTemplate, certificateTemplateSigner *x509.Certificate, privateKey, privateKeySigner *rsa.PrivateKey) ([]byte, error) {
	certificate, err := x509.CreateCertificate(rand.Reader, certificateTemplate, certificateTemplateSigner, &privateKey.PublicKey, privateKeySigner)
	if err != nil {
		return nil, err
	}

	return encodeCertificate(certificate), err
}

func generateCertificateTemplate(commonName string, organization []string, isCA bool, certType string) *x509.Certificate {
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		IsCA: isCA,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // + 10 years
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: organization,
		},
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		switch certType {
		case "server":
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		case "client":
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
	}
	return template
}

func main() {
	cn := os.Getenv("CN")
	isCA := os.Getenv("IS_CA") == "true"
	certType := os.Getenv("CERT_TYPE")
	organization := []string{"ZH", "SH", "SH", "SAP", "CP"}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	privateKeyPEM := encodePrivateKey(privateKey)
	tmpl := generateCertificateTemplate(cn, organization, isCA, certType)

	if isCA {
		certPEM, err := signCertificate(tmpl, tmpl, privateKey, privateKey)
		if err != nil {
			panic(err)
		}
		ioutil.WriteFile("ca.crt", certPEM, 0666)
		ioutil.WriteFile("ca.key", privateKeyPEM, 0666)

	} else {
		caCrtPEM, err := ioutil.ReadFile("ca.crt")
		if err != nil {
			panic(err)
		}
		caKeyPEM, err := ioutil.ReadFile("ca.key")
		if err != nil {
			panic(err)
		}
		caCrt, err := decodeCertificate(caCrtPEM)
		if err != nil {
			panic(err)
		}
		caKey, err := decodePrivateKey(caKeyPEM)
		if err != nil {
			panic(err)
		}

		certPEM, err := signCertificate(tmpl, caCrt, privateKey, caKey)
		if err != nil {
			panic(err)
		}
		ioutil.WriteFile(fmt.Sprintf("%s.crt", cn), certPEM, 0666)
		ioutil.WriteFile(fmt.Sprintf("%s.key", cn), privateKeyPEM, 0666)
	}

}
