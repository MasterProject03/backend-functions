package backendfunctions

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
)

var authRouter *mux.Router

func init() {
	authRouter = mux.NewRouter().StrictSlash(false)
	authRouter.Path("/login").Methods(http.MethodPost).HandlerFunc(WithJSON(login))
	authRouter.Path("/ca").Methods(http.MethodGet).HandlerFunc(WithJSON(getAuthCA))
	authRouter.Path("/token/{token}").Methods(http.MethodGet).HandlerFunc(WithJSON(validateToken))
	authRouter.Path("/token/{token}/refresh").Methods(http.MethodPut).HandlerFunc(WithJSON(refreshToken))
	authRouter.NotFoundHandler = WithJSON(NotFoundHTTP)
}

func AuthHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authRouter.ServeHTTP(w, r)
}

func GetAuthKey() (*rsa.PrivateKey, error) {
	pemString := os.Getenv("JWT_PRIVATE_KEY")

	pemBlock, _ := pem.Decode([]byte(pemString))
	privateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func GetAuthCA() (*rsa.PublicKey, error) {
	privateKey, err := GetAuthKey()
	if err != nil {
		return nil, err
	}

	return &privateKey.PublicKey, nil
}

func login(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	var d struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !ParseBody(&d, w, out, r) {
		return
	}

	key, user, err := GetUserByEmail(d.Email)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to lookup user",
			"trace": err.Error(),
		})
		return
	}
	if user == nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "unknown email",
			"trace": nil,
		})
		return
	}

	pemBlock, _ := pem.Decode(user.PrivateKey)
	_, err = x509.DecryptPEMBlock(pemBlock, []byte(d.Password))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "incorrect password",
			"trace": err.Error(),
		})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
		"iss":               "mackee-news",
		"iat":               time.Now().Unix(),
		"exp":               time.Now().Add(time.Hour * 24).Unix(),
		"sub":               key.Encode(),
		"first_name":        user.FirstName,
		"last_name":         user.LastName,
		"email":             user.Email,
		"key_hash":          user.KeyHash,
		"moderator":         strconv.FormatBool(user.Moderator),
		"registration_date": user.RegistrationDate.String(),
	})

	jwtPrivateKey, err := GetAuthKey()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to parse private key",
			"trace": err.Error(),
		})
		return
	}

	jwtString, err := token.SignedString(jwtPrivateKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to retrieve signing key",
			"trace": err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	out.Encode(map[string]interface{}{
		"token": jwtString,
	})
}

func getAuthCA(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	jwtPublicKey, err := GetAuthCA()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to parse public key",
			"trace": err.Error(),
		})
		return
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(jwtPublicKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to format public key",
			"trace": err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	out.Encode(map[string]interface{}{
		"pem": string(pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		})),
	})
}

func validateToken(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	tokenString := mux.Vars(r)["token"]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
		}

		jwtPublicKey, err := GetAuthCA()
		if err != nil {
			return nil, err
		}

		return jwtPublicKey, nil
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to parse token",
			"trace": err.Error(),
		})
		return
	}

	if !token.Valid {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "invalid token",
			"trace": nil,
		})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to parse claims",
			"trace": err.Error(),
		})
		return
	}
	if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "token expired",
			"trace": nil,
		})
		return
	}
	if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "token not yet valid",
			"trace": nil,
		})
		return
	}
	if !claims.VerifyIssuer("mackee-news", true) {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "token issuer mismatch",
			"trace": nil,
		})
		return
	}

	userId, ok := claims["sub"].(string)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to retrieve user ID",
			"trace": err.Error(),
		})
		return
	}
	_, _, err = GetUserById(userId)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to fetch user",
			"trace": err.Error(),
		})
		return
	}

	// TODO: Add warnings if some fields are out of date

	w.WriteHeader(http.StatusOK)
	out.Encode(map[string]interface{}{
		"valid": true,
	})
}

func refreshToken(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	tokenString := mux.Vars(r)["token"]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
		}

		jwtPublicKey, err := GetAuthCA()
		if err != nil {
			return nil, err
		}

		return jwtPublicKey, nil
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to parse token",
			"trace": err.Error(),
		})
		return
	}

	if !token.Valid {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "invalid token",
			"trace": nil,
		})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to parse claims",
			"trace": err.Error(),
		})
		return
	}
	if !claims.VerifyIssuer("mackee-news", true) {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "token issuer mismatch",
			"trace": nil,
		})
		return
	}

	userId, ok := claims["sub"].(string)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to retrieve user ID",
			"trace": err.Error(),
		})
		return
	}
	key, user, err := GetUserById(userId)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to fetch user",
			"trace": err.Error(),
		})
		return
	}

	newToken := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
		"iss":               "mackee-news",
		"iat":               time.Now().Unix(),
		"exp":               time.Now().Add(time.Hour * 24).Unix(),
		"sub":               key.Encode(),
		"first_name":        user.FirstName,
		"last_name":         user.LastName,
		"email":             user.Email,
		"key_hash":          user.KeyHash,
		"moderator":         strconv.FormatBool(user.Moderator),
		"registration_date": user.RegistrationDate.String(),
	})

	jwtPrivateKey, err := GetAuthKey()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to parse private key",
			"trace": err.Error(),
		})
		return
	}

	jwtString, err := newToken.SignedString(jwtPrivateKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to retrieve signing key",
			"trace": err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	out.Encode(map[string]interface{}{
		"token": jwtString,
	})
}
