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

	CACertificate *x509.Certificate
	CAPrivateKey  *rsa.PrivateKey
}

func NewCertGenerator(path string, notAfter time.Time) *CertGenerator {
	return &CertGenerator{
		path:     path,
		notAfter: notAfter,
	}
}

// 1. Generate CA's private key and self-signed certificate
// Generate a Certificate Authority
func (c *CertGenerator) GenerateCA(name pkix.Name) error {
	// Check if the CA already exists
	if err := c.LoadCA(); err == nil {
		return nil
	}

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

// Load the CA certificate and private key
func (c *CertGenerator) LoadCA() error {
	if c.CACertificate != nil && c.CAPrivateKey != nil {
		return nil
	}

	// Read the CA certificate and private key
	caCertPEM, err := os.ReadFile(c.path + "/ca-cert.pem")
	if err != nil {
		return err
	}

	caCertBlock, _ := pem.Decode(caCertPEM)

	if c.CACertificate, err = x509.ParseCertificate(caCertBlock.Bytes); err != nil {
		return err
	}

	caKeyPEM, err := os.ReadFile(c.path + "/ca-key.pem")
	if err != nil {
		return err
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)

	if c.CAPrivateKey, err = x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes); err != nil {
		return err
	}

	return nil
}

// 2. Generate web server's private key and certificate signing request (CSR)
// 3. Use CA's private key to sign web server's CSR and get back the signed certificate
// Generate a Certificate
func (c *CertGenerator) GenerateServerCert(name pkix.Name, ipAddresses []net.IP) error {
	// Read the CA certificate and private key
	if err := c.LoadCA(); err != nil {
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
	serverBytes, err := x509.CreateCertificate(rand.Reader, &serverTemplate, c.CACertificate, &serverPrivKey.PublicKey, c.CAPrivateKey)
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

// 4. Generate client's private key and certificate signing request (CSR)
// 5. Use CA's private key to sign client's CSR and get back the signed certificate
func (c *CertGenerator) GenerateClientCert(name pkix.Name, ipAddresses []net.IP) error {
	// Read the CA certificate and private key
	if err := c.LoadCA(); err != nil {
		return err
	}

	// Generate a private key for the client
	clientPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Generate a certificate for the client
	clientTemplate := x509.Certificate{
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
	clientBytes, err := x509.CreateCertificate(rand.Reader, &clientTemplate, c.CACertificate, &clientPrivKey.PublicKey, c.CAPrivateKey)
	if err != nil {
		return err
	}

	// Save the certificate and private key
	certOut, err := os.Create(c.path + "/client-cert.pem")
	if err != nil {
		return err
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: clientBytes})

	keyOut, err := os.OpenFile(c.path+"/client-key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientPrivKey)})

	return nil
}
