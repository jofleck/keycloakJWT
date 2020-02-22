package keycloakJWT

import (
	"encoding/json"
	"net/http"
)

func GetRealmRSAPublicKey(realmUrl string) ([]byte, error) {
	response, err := http.Get(realmUrl)
	if err != nil {
		return nil, err
	}
	var realm RealmDTO
	json.NewDecoder(response.Body).Decode(&realm)
	key := "-----BEGIN PUBLIC KEY-----\n" + realm.PublicKey + "\n-----END PUBLIC KEY-----"
	return []byte(key), nil
}
