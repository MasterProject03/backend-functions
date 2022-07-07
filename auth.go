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
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
)

var authRouter *mux.Router

func init() {
	authRouter = mux.NewRouter().StrictSlash(false)
	authRouter.Path("/me").Methods(http.MethodGet).HandlerFunc(WithJSON(getMe))
	authRouter.Path("/login").Methods(http.MethodPost).HandlerFunc(WithJSON(login))
	authRouter.Path("/ca").Methods(http.MethodGet).HandlerFunc(WithJSON(getAuthCA))
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

func ParseToken(tokenString string, allowExpired bool, fetch bool) (*datastore.Key, *User, error) {
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
		return nil, nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, nil, fmt.Errorf("verification failed")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, fmt.Errorf("failed to parse claims: %w", err)
	} else if !claims.VerifyIssuer("mackee-news", true) {
		return nil, nil, fmt.Errorf("token issuer mismatch")
	} else if !claims.VerifyIssuedAt(time.Now().Unix(), true) {
		return nil, nil, fmt.Errorf("token not yet valid")
	} else if !allowExpired && !claims.VerifyExpiresAt(time.Now().Unix(), true) {
		return nil, nil, fmt.Errorf("token expired")
	}

	userId, ok := claims["sub"].(string)
	if !ok {
		return nil, nil, fmt.Errorf("failed to retrieve user ID: %w", err)
	}

	var key *datastore.Key
	var user *User
	if fetch {
		key, user, err = GetUserById(userId)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch user: %w", err)
		}
	} else {
		key, err = datastore.DecodeKey(userId)
		if err != nil {
			return nil, nil, err
		}

		firstName, ok := claims["first_name"].(string)
		if !ok {
			return nil, nil, fmt.Errorf("failed to retrieve user first_name: %w", err)
		}
		lastName, ok := claims["last_name"].(string)
		if !ok {
			return nil, nil, fmt.Errorf("failed to retrieve user last_name: %w", err)
		}
		email, ok := claims["email"].(string)
		if !ok {
			return nil, nil, fmt.Errorf("failed to retrieve user email: %w", err)
		}
		keyHash, ok := claims["key_hash"].(string)
		if !ok {
			return nil, nil, fmt.Errorf("failed to retrieve user key_hash: %w", err)
		}
		moderatorString, ok := claims["moderator"].(string)
		if !ok {
			return nil, nil, fmt.Errorf("failed to retrieve user moderator: %w", err)
		}
		moderator, err := strconv.ParseBool(moderatorString)
		if err != nil {
			return nil, nil, err
		}
		registrationDateString, ok := claims["registration_date"].(string)
		if !ok {
			return nil, nil, fmt.Errorf("failed to retrieve user registration_date: %w", err)
		}
		registrationDate, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", registrationDateString)
		if err != nil {
			return nil, nil, err
		}

		user = &User{
			FirstName:        firstName,
			LastName:         lastName,
			Email:            email,
			KeyHash:          keyHash,
			Moderator:        moderator,
			RegistrationDate: registrationDate,
		}
	}

	return key, user, nil
}

func GetAuthUser(r *http.Request) (*datastore.Key, *User, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return nil, nil, fmt.Errorf("missing authorization header")
	} else if !strings.HasPrefix(header, "Bearer ") {
		return nil, nil, fmt.Errorf("invalid authorization type")
	}

	token := strings.TrimPrefix(header, "Bearer ")

	key, user, err := ParseToken(token, false, false)
	if err != nil {
		return nil, nil, err
	}

	return key, user, nil
}

func getMe(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	key, user, err := GetAuthUser(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		out.Encode(map[string]interface{}{
			"error": "unauthorized",
			"trace": err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	out.Encode(map[string]interface{}{
		"id":                key.Encode(),
		"first_name":        user.FirstName,
		"last_name":         user.LastName,
		"email":             user.Email,
		"key_hash":          user.KeyHash,
		"moderator":         strconv.FormatBool(user.Moderator),
		"registration_date": user.RegistrationDate.String(),
	})
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
	} else if user == nil {
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
			"error": "failed to parse private key",
			"trace": err.Error(),
		})
		return
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(jwtPublicKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to extract public key",
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

func refreshToken(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	tokenString := mux.Vars(r)["token"]

	key, user, err := ParseToken(tokenString, true, true)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		out.Encode(map[string]interface{}{
			"valid": true,
			"error": "invalid token",
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
