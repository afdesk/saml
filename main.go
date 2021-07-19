package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"github.com/afdesk/saml/tokenservice"
	"github.com/crewjam/saml/samlsp"
	"log"
	"net/http"
	"net/url"
	"os"
)

var sessioncert = "./sessioncert"
var sessionkey = "./sessionkey"

var serverurl = "https://auth.aquasec.com"
var callbackUrl = "https://nginx.aquasec.com"

const cookieToken = "saml_cookie"
const cookieUserName = "saml_user"

func index(w http.ResponseWriter, r *http.Request) {
	u, err := r.Cookie(cookieUserName)
	if err != nil {
		log.Print("The cookie for a user doesn't exist")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	c, err := r.Cookie(cookieToken)
	if err != nil || !tokenservice.IsCorrectUser(c.Value, u.Value, sessionkey) {
		log.Print("The cookie for a token has problems")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func ok(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func hello(w http.ResponseWriter, r *http.Request) {
	s := samlsp.SessionFromContext(r.Context())
	if s == nil {
		return
	}
	sa, ok := s.(samlsp.SessionWithAttributes)
	if !ok {
		log.Printf("Auth0 didn't return SessionWithAttributes")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	user := sa.GetAttributes().Get("http://schemas.auth0.com/nickname")

	u := &http.Cookie{
		Name:  cookieUserName,
		Value: user,
		Domain: "aquasec.com",
		Path:  "/",
	}

	c := &http.Cookie{
		Name:  cookieToken,
		Value: tokenservice.GetJWT(user, sessionkey),
		Domain: "aquasec.com",
		Path:  "/",
	}
	http.SetCookie(w, c)
	http.SetCookie(w, u)
	http.Redirect(w,r, callbackUrl, http.StatusSeeOther)
}

func main() {
	keyPair, err := tls.LoadX509KeyPair(sessioncert, sessionkey)
	panicIfError(err)

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	panicIfError(err)

	idpMetadataURL, err := url.Parse(os.Getenv("AUTH0_METADATA_URL"))
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
	http.HandleFunc("/ok", ok)
	http.Handle("/hello", samlSP.RequireAccount(app))
	http.Handle("/saml/", samlSP)

	log.Printf("Server is running... go to %s/hello\n", serverurl)
	panicIfError(http.ListenAndServe(":8000", nil))
}
func panicIfError(err error) {
	if err != nil {
		panic(err)
	}
}
