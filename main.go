package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/afdesk/saml/tokenservice"
	"github.com/crewjam/saml/samlsp"
	"net/http"
	"net/url"
	"os"
)

var metadataurl = "https://dev-phuduzc4.eu.auth0.com/samlp/metadata/"
var sessioncert = "./sessioncert"
var sessionkey = "./sessionkey"

//var serverurl = "http://127.0.0.1:8000"
var serverurl = "http://mysaml.com"

const cookieToken = "saml_cookie"
const cookieUserName = "saml_user"
const endpoint = "http://google.com"

func index(w http.ResponseWriter, r *http.Request) {
	u, err := r.Cookie(cookieUserName)
	if err != nil {
		http.Redirect(w, r, "/hello", http.StatusSeeOther)
		return
	}
	c, err := r.Cookie(cookieToken)
	if err != nil || !tokenservice.IsCorrectUser(c.Value, u.Value, sessionkey) {
		http.Redirect(w, r, "/hello", http.StatusSeeOther)
		return
	}
	http.SetCookie(w, c)
	http.SetCookie(w, u)
	http.Redirect(w, r, endpoint, http.StatusSeeOther)
}

func hello(w http.ResponseWriter, r *http.Request) {
	s := samlsp.SessionFromContext(r.Context())
	if s == nil {
		return
	}
	sa, ok := s.(samlsp.SessionWithAttributes)
	if !ok {
		return
	}
	user := sa.GetAttributes().Get("http://schemas.auth0.com/nickname")

	u := &http.Cookie{
		Name:   cookieUserName,
		Value:  user,
		Path:   "/",
	}

	c := &http.Cookie{
		Name:   cookieToken,
		Value:  tokenservice.GetJWT(user, sessionkey),
		Path:   "/",
	}
	http.SetCookie(w, c)
	http.SetCookie(w, u)
	http.Redirect(w, r, endpoint, http.StatusSeeOther)
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
		AllowIDPInitiated: true,
		URL:               *rootURL,
		Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:       keyPair.Leaf,
		IDPMetadata:       idpMetadata,
	})
	app := http.HandlerFunc(hello)
	http.HandleFunc("/", index)
	http.Handle("/hello", samlSP.RequireAccount(app))
	http.Handle("/saml/", samlSP)
	fmt.Print("Server is running...")
	panicIfError(http.ListenAndServe(":8000", nil))
}
func panicIfError(err error) {
	if err != nil {
		panic(err)
	}
}
