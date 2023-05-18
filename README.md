# go-cert


var serverCertName pkix.Name = pkix.Name{
	CommonName:    "Server Cert",
	Organization:  []string{"Cerver Operator"},
	Country:       []string{"US"},
	Province:      []string{""},
	Locality:      []string{"San Francisco"},
	StreetAddress: []string{"Golden Gate Bridge"},
	PostalCode:    []string{"94016"},
}

var serverTemplate x509.Certificate = x509.Certificate{
	SerialNumber: big.NewInt(2),
	Subject:      name,
	IPAddresses:  ipAddresses,
	NotBefore:    time.Now(),
	NotAfter:     c.notAfter,
	SubjectKeyId: []byte{1, 2, 3, 4, 6},
	ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	KeyUsage:     x509.KeyUsageDigitalSignature,
}

if err = c.GenerateServerCert(serverCertName, serverTemplate); err != nil {
	log.Println(err)
	return tlsCredentials, err
}

// -------------------------------------------------

var clientCertName pkix.Name = pkix.Name{
	CommonName:    "Informer Cert",
	Organization:  []string{"Client Operator"},
	Country:       []string{"US"},
	Province:      []string{""},
	Locality:      []string{"San Francisco"},
	StreetAddress: []string{"Golden Gate Bridge"},
	PostalCode:    []string{"94016"},
}

var clientTemplate x509.Certificate = x509.Certificate{
	SerialNumber: big.NewInt(2),
	Subject:      name,
	IPAddresses:  ipAddresses,
	NotBefore:    time.Now(),
	NotAfter:     c.notAfter,
	SubjectKeyId: []byte{1, 2, 3, 4, 6},
	ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	KeyUsage:     x509.KeyUsageDigitalSignature,
}

if err = c.GenerateClientCert(clientCertName, clientTemplate); err != nil {
	log.Println(err)
	return err
}
