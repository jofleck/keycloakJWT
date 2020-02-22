package keycloakJWT

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/mitchellh/mapstructure"
	"net/http"
	"strings"
	"time"
)

var realmUrl string
var lastUpdated time.Time
var key []byte
var cacheTime int

func Init(pUrl string, pCacheTime int) {
	realmUrl = pUrl
	cacheTime = pCacheTime
}

func ExtractTokenWithScope(r *http.Request, scope string) (JWTModel, bool, error) {
	token, err := ExtractToken(r)
	if err != nil {
		return JWTModel{}, false, err
	}
	ok := containsString(strings.Split(token.Scope, " "), scope)
	return token, ok, nil
}

func ExtractToken(r *http.Request) (JWTModel, error) {
	if realmUrl == "" {
		return JWTModel{}, errors.New("realm URL not set")
	}
	if lastUpdated.Before(time.Now().Add(-5 * time.Minute)) {
		fmt.Println("fetching realm public key")
		keyTmp, err := GetRealmRSAPublicKey(realmUrl)
		lastUpdated = time.Now()
		if err != nil {
			return JWTModel{}, err
		}
		key = keyTmp
	}
	return ExtractTokenFromPublicKey(r, key)
}

func ExtractTokenFromPublicKey(r *http.Request, publicKey []byte) (JWTModel, error) {
	const BEARER_SCHEMA = "Bearer "
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) <= len(BEARER_SCHEMA) {
		return JWTModel{}, errors.New("no token provided")
	}

	tokenString := authHeader[len(BEARER_SCHEMA):]
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return jwt.ParseRSAPublicKeyFromPEM(publicKey)
	})
	if err != nil {
		return JWTModel{}, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		var jwtModel JWTModel
		err := mapstructure.Decode(claims, &jwtModel)
		return jwtModel, err

	} else {
		return JWTModel{}, err
	}
}

func containsString(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}
