package tunnels

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
)

func saveJson(data interface{}, filePath string) error {
	jsonStr, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return errors.New("error serializing JSON")
	} else {
		err := os.WriteFile(filePath, jsonStr, 0644)
		if err != nil {
			return errors.New("error saving JSON")
		}
	}
	return nil
}

// Looks for auth token in query string, then headers, then cookies
func extractToken(tokenName string, r *http.Request) (string, error) {

	query := r.URL.Query()

	queryToken := query.Get(tokenName)
	if queryToken != "" {
		return queryToken, nil
	}

	tokenHeader := r.Header.Get(tokenName)
	if tokenHeader != "" {
		return tokenHeader, nil
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		tokenHeader := strings.Split(authHeader, " ")[1]
		return tokenHeader, nil
	}

	tokenCookie, err := r.Cookie(tokenName)
	if err == nil {
		return tokenCookie.Value, nil
	}

	return "", errors.New("no token found")
}

const chars string = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func genRandomCode(length int) (string, error) {
	id := ""
	for i := 0; i < length; i++ {
		randIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		id += string(chars[randIndex.Int64()])
	}
	return id, nil
}

func randomOpenPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}

	addrParts := strings.Split(listener.Addr().String(), ":")
	port, err := strconv.Atoi(addrParts[len(addrParts)-1])
	if err != nil {
		return 0, err
	}

	listener.Close()

	return port, nil
}

func stringInArray(value string, array []string) bool {
	return slices.Contains(array, value)
}
