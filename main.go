package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"

	"golang.org/x/crypto/ocsp"
)

type Body struct {
	Certificates        []*x509.Certificate
	VerificationResults []string
	OcspResults         []string
	CrlResults          []string
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>Certificate Data</title>
	</head>
	<body>
		<h1>Certificate Data</h1>
		<ul>
			{{range $i, $c := .Certificates}}
				<li>Certificate {{$i}}</li>
				<ul>
					<li>Verification Result: {{index $.VerificationResults $i}}</li>
					<li>OCSP Result: {{index $.OcspResults $i}}</li>
					<li>CRL Result: {{index $.CrlResults $i}}</li>
					<li>Issuer: {{$c.Issuer.String}}</li>
					<li>Subject: {{$c.Subject.String}}</li>
					<li>NotBefore: {{$c.NotBefore}}</li>
					<li>NotAfter: {{$c.NotAfter}}</li>
					<li>SignatureAlgorithm: {{$c.SignatureAlgorithm}}</li>
					<li>PublicKeyAlgorithm: {{$c.PublicKeyAlgorithm}}</li>
					<li>Version: {{$c.Version}}</li>
					<li>SerialNumber: {{$c.SerialNumber}}</li>
					<li>KeyUsage: {{$c.KeyUsage}}</li>
					<li>ExtKeyUsage: {{$c.ExtKeyUsage}}</li>
					<li>BasicConstraintsValid: {{$c.BasicConstraintsValid}}</li>
					<li>IsCA: {{$c.IsCA}}</li>
					<li>MaxPathLen: {{$c.MaxPathLen}}</li>
					<li>MaxPathLenZero: {{$c.MaxPathLenZero}}</li>
					<li>SubjectKeyId: {{$c.SubjectKeyId}}</li>
					<li>AuthorityKeyId: {{$c.AuthorityKeyId}}</li>
					<li>OCSPServer: {{$c.OCSPServer}}</li>
					<li>IssuingCertificateURL: {{$c.IssuingCertificateURL}}</li>
					<li>DNSNames: {{$c.DNSNames}}</li>
					<li>EmailAddresses: {{$c.EmailAddresses}}</li>
					<li>IPAddresses: {{$c.IPAddresses}}</li>
					<li>URIs: {{$c.URIs}}</li>
					<li>PermittedDNSDomainsCritical: {{$c.PermittedDNSDomainsCritical}}</li>
					<li>PermittedDNSDomains: {{$c.PermittedDNSDomains}}</li>
					<li>ExcludedDNSDomains: {{$c.ExcludedDNSDomains}}</li>
					<li>PermittedIPRanges: {{$c.PermittedIPRanges}}</li>
					<li>ExcludedIPRanges: {{$c.ExcludedIPRanges}}</li>
					<li>PermittedEmailAddresses: {{$c.PermittedEmailAddresses}}</li>
					<li>ExcludedEmailAddresses: {{$c.ExcludedEmailAddresses}}</li>
					<li>PermittedURIDomains: {{$c.PermittedURIDomains}}</li>
					<li>ExcludedURIDomains: {{$c.ExcludedURIDomains}}</li>
					<li>CRLDistributionPoints: {{$c.CRLDistributionPoints}}</li>
					<li>PolicyIdentifiers: {{$c.PolicyIdentifiers}}</li>
				</ul>
			{{end}}
		</ul>
	</body>
	</html>`

	certificates := r.TLS.PeerCertificates
	body := Body{
		Certificates:        certificates,
		VerificationResults: make([]string, len(certificates)),
		OcspResults:         make([]string, len(certificates)),
		CrlResults:          make([]string, len(certificates)),
	}

	certPool := getCertPool()
	verifyOptions := x509.VerifyOptions{
		Roots:         certPool,
		Intermediates: certPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	for i, cert := range certificates {
		chain, err := cert.Verify(verifyOptions)
		if err != nil {
			body.VerificationResults[i] = fmt.Sprintf("%v", err)
			body.OcspResults[i] = "Cert verification failed. Not attempting OCSP check."
			body.CrlResults[i] = "Cert verification failed. Not attempting CRL check."
		} else {
			body.VerificationResults[i] = "Success"
			ocspResponse, err := getOcspResponse(chain[0])
			if err != nil {
				body.OcspResults[i] = fmt.Sprintf("%v", err)
			} else {
				body.OcspResults[i] = ocspResponse

			}

			crlResponse, err := checkCertAgainstCrl(cert)
			if err != nil {
				body.CrlResults[i] = fmt.Sprintf("%v", err)
			} else {
				body.CrlResults[i] = crlResponse
			}
		}
	}

	t, err := template.New("body").Parse(tmpl)
	if err != nil {
		log.Fatal(err)
	}

	err = t.Execute(w, body)
	if err != nil {
		log.Fatal(err)
	}
}

func checkCertAgainstCrl(cert *x509.Certificate) (status string, err error) {
	if cert.CRLDistributionPoints == nil || cert.CRLDistributionPoints[0] == "" {
		return "No CRL Distribution Points found. Not attempting CRL check.", nil
	}

	httpRequest, err := http.NewRequest(http.MethodGet, cert.CRLDistributionPoints[0], nil)
	if err != nil {
		log.Fatal(err)
	}
	crlUrl, err := url.Parse(cert.CRLDistributionPoints[0])
	if err != nil {
		log.Fatal(err)
	}
	httpRequest.Header.Add("Host", crlUrl.Host)
	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		log.Fatal(err)
	}
	defer httpResponse.Body.Close()
	output, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		log.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(output)
	if err != nil {
		log.Fatal(err)
	}
	for _, revokedCert := range crl.RevokedCertificates {
		if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			errorString := fmt.Sprintf("Certificate %s IS revoked", cert.Subject.CommonName)
			return errorString, errors.New(errorString)
		}
	}

	return fmt.Sprintf("Certificate %s IS NOT revoked", cert.Subject.CommonName), nil
}

func main() {
	log.Print("Starting up...")

	// Set up a /hello resource handler
	http.HandleFunc("/", helloHandler)

	// Create a CA certificate pool
	caCertPool := getCertPool()

	// Iterate over files in cacerts and add them to the CA certificate pool
	files, err := ioutil.ReadDir("cacerts")
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		if !file.IsDir() {
			cert, err := ioutil.ReadFile("cacerts/" + file.Name())
			if err != nil {
				log.Fatal(err)
			}
			caCertPool.AppendCertsFromPEM(cert)
		}
	}

	// Read certificate from file
	serverCert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
	}

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		// RootCAs:               caCertPool,
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		// VerifyPeerCertificate: verifyPeerCertificate,
	}
	tlsConfig.BuildNameToCertificate()

	// Create a Server instance to listen on port 8443 with the TLS config
	server := &http.Server{
		Addr:      ":443",
		TLSConfig: tlsConfig,
	}

	log.Print("Starting server on :443")

	// Listen to HTTPS connections with the server certificate and wait
	log.Fatal(server.ListenAndServeTLS("cert.pem", "key.pem"))
}

func getCertPool() *x509.CertPool {
	// Create a CA certificate pool and add cert.pem to it
	caCert, err := os.ReadFile("cert.pem")
	if err != nil {
		log.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Iterate over files in cacerts and add them to the CA certificate pool
	files, err := os.ReadDir("cacerts")
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		if !file.IsDir() {
			cert, err := os.ReadFile("cacerts/" + file.Name())
			if err != nil {
				log.Fatal(err)
			}
			caCertPool.AppendCertsFromPEM(cert)
		}
	}
	return caCertPool
}

func getOcspResponse(chain []*x509.Certificate) (status string, err error) {
	if len(chain) < 2 {
		return fmt.Sprintf("%s is self-signed. Not attempting OCSP request.\n", chain[0].Subject.CommonName), nil
	}

	if chain[0].OCSPServer == nil || chain[0].OCSPServer[0] == "" {
		return fmt.Sprintf("%s does not have an OCSP server. Not attempting OCSP request.\n", chain[0].Subject.CommonName), nil
	}

	buffer, err := ocsp.CreateRequest(chain[0], chain[1], nil)
	if err != nil {
		log.Fatal(err)
	}

	httpRequest, err := http.NewRequest(http.MethodPost, chain[0].OCSPServer[0], bytes.NewBuffer(buffer))
	if err != nil {
		log.Fatal(err)
	}
	ocspUrl, err := url.Parse(chain[0].OCSPServer[0])
	if err != nil {
		log.Fatal(err)
	}
	httpRequest.Header.Add("Host", ocspUrl.Host)
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		log.Fatal(err)
	}
	defer httpResponse.Body.Close()
	output, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		log.Fatal(err)
	}
	ocspResponse, err := ocsp.ParseResponseForCert(output, chain[0], chain[1])
	if err != nil {
		log.Fatal(err)
	}

	if ocspResponse.Status != ocsp.Good {
		errorString := fmt.Sprintf("OCSP status for %s is %d", chain[0].Subject.CommonName, ocspResponse.Status)
		return errorString, errors.New(errorString)
	} else {
		return fmt.Sprintf("OCSP status for %s is Good\n", chain[0].Subject.CommonName), nil
	}
}
