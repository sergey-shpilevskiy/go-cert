package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

func LoadTLSCredentials(certFile, keyFile string) (credentials.TransportCredentials, error) {
	// Load server's certificate and private key
	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	// Create the credentials and return it
	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
	}

	return credentials.NewTLS(config), nil
}

func LoadTLSCredentialsFromCA(caCertFile string) (credentials.TransportCredentials, error) {
	// Load certificate of the CA who signed server's certificate
	pemServerCA, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemServerCA) {
		return nil, fmt.Errorf("failed to add server CA's certificate")
	}

	// Create the credentials and return it
	config := &tls.Config{
		RootCAs: certPool,
	}

	return credentials.NewTLS(config), nil
}
