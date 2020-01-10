package services

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

// CACert ... new()
var CACert = new(x509.CertPool)

// GetCertPool gets the configuration values for the api
func GetCertPool() *x509.CertPool {
	newCert := x509.NewCertPool()
	caCert, err := ioutil.ReadFile(os.Getenv(`CA_BUNDLE_PATH`))
	if err != nil {
		log.Printf("Unable to load CA Bundle: %v", err)
	} else {
		if !newCert.AppendCertsFromPEM(caCert) {
			log.Println("Unable to add CA Bundle to LRAPICLIENT")
		}
	}
	return newCert
}

// HTTPClient ...
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
	PostForm(url string, values url.Values) (resp *http.Response, err error)
}

// NewClient ...
func NewClient() HTTPClient {
	const TIMEOUT = 10
	caCert := GetCertPool()
	var client HTTPClient
	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCert,
			},
			Dial: (&net.Dialer{
				Timeout: time.Duration(TIMEOUT) * time.Second,
			}).Dial,
		},
	}
	return client
}
