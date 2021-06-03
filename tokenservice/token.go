package tokenservice

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	jwt "github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"log"
)

var (
	errNoPem = errors.New("PEM file doesn't exist")
)

func getPrivateKey(filename string) (interface{}, error) {
	pemData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errNoPem
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func GetJWT(user, filename string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
		"user": user,
	})
	priv, err := getPrivateKey(filename)
	if err != nil {
		log.Printf("token.SignedString error: %v", err)
		return ""
	}
	tokenString, err := token.SignedString(priv)
	if err != nil {
		log.Printf("token.SignedString error: %v", err)
		return ""
	}

	return tokenString
}

func IsCorrectUser(token, user, filename string) bool {
	return token == GetJWT(user, filename)
}
