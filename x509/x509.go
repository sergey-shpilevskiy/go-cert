package x509

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"
)

type CertGenerator struct {
	path     string
	notAfter time.Time

	// caCertFileName string
	// caKeyFileName  string
	// certFileName   string
	// keyFileName    string
}

// func NewCertGenerator(caCertFileName, caKeyFileName, certFileName, keyFileName string, notAfter time.Time) *CertGenerator {
func NewCertGenerator(path string, notAfter time.Time) *CertGenerator {
	return &CertGenerator{
		path:     path,
		notAfter: notAfter,

		// caCertFileName: caCertFileName,
		// caKeyFileName:  caKeyFileName,
		// certFileName:   certFileName,
		// keyFileName:    keyFileName,
	}
}

// Generate a Certificate Authority
func (c *CertGenerator) GenerateCA(name pkix.Name) error {
	// Generate a private key for the CA
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Generate a self-signed certificate for the CA
	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               name,
		NotBefore:             time.Now(),
		NotAfter:              c.notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		// ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		// KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	// Create a new certificate template
	caBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	// Save the certificate and private key
	certOut, err := os.Create(c.path + "/ca-cert.pem")
	if err != nil {
		return err
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})

	keyOut, err := os.OpenFile(c.path+"/ca-key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey)})

	return nil
}

// Generate a Certificate
func (c *CertGenerator) GenerateCert(name pkix.Name, ipAddresses []net.IP) error {
	// Read the CA certificate and private key
	caCertPEM, err := os.ReadFile(c.path + "/ca-cert.pem")
	if err != nil {
		return err
	}
	caCertBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return err
	}

	caKeyPEM, err := os.ReadFile(c.path + "/ca-key.pem")
	if err != nil {
		return err
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return err
	}

	// Generate a private key for the server
	serverPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Generate a certificate for the server
	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      name,
		IPAddresses:  ipAddresses,
		NotBefore:    time.Now(),
		NotAfter:     c.notAfter,
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// Create a new certificate template
	serverBytes, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caCert, &serverPrivKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	// Save the certificate and private key
	certOut, err := os.Create(c.path + "/server-cert.pem")
	if err != nil {
		return err
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: serverBytes})

	keyOut, err := os.OpenFile(c.path+"/server-key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverPrivKey)})

	return nil
}
