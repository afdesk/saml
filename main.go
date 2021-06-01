package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/crewjam/saml/samlsp"
)

var metadataurl = "https://dev-phuduzc4.eu.auth0.com/samlp/metadata/"
var sessioncert = "./sessioncert"
var sessionkey = "./sessionkey"
var serverurl = "http://127.0.0.1:8000"

func hello(w http.ResponseWriter, r *http.Request) {
	s := samlsp.SessionFromContext(r.Context())
	if s == nil {
		return
	}
	sa, ok := s.(samlsp.SessionWithAttributes)
	if !ok {
		return
	}
	fmt.Fprintf(w, "Hello, %s!", sa.GetAttributes().Get("http://schemas.auth0.com/nickname"))
}

func main() {
	keyPair, err := tls.LoadX509KeyPair(sessioncert, sessionkey)
	panicIfError(err)

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	panicIfError(err)

	idpMetadataURL, err := url.Parse(metadataurl + os.Getenv("AUTH0_ID"))
	panicIfError(err)

	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient, *idpMetadataURL)
	panicIfError(err)

	rootURL, err := url.Parse(serverurl)
	panicIfError(err)
	samlSP, _ := samlsp.New(samlsp.Options{
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
	})
	app := http.HandlerFunc(hello)
	http.Handle("/hello", samlSP.RequireAccount(app))
	http.Handle("/saml/", samlSP)
	panicIfError(http.ListenAndServe(":8000", nil))
}
func panicIfError(err error) {
	if err != nil {
		panic(err)
	}
}
