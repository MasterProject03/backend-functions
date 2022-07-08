package backendfunctions

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/gorilla/mux"
	"google.golang.org/api/iterator"
)

type User struct {
	FirstName        string
	LastName         string
	Email            string
	PrivateKey       string `datastore:",noindex"`
	PublicKey        string
	Moderator        bool
	RegistrationDate time.Time
}

var accountsRouter *mux.Router

func init() {
	accountsRouter = mux.NewRouter().StrictSlash(false)
	accountsRouter.Path("/").Methods(http.MethodPost).HandlerFunc(WithJSON(createUser))
	accountsRouter.Path("/{id}").Methods(http.MethodGet).HandlerFunc(WithJSON(getUser))
	accountsRouter.Path("/{id}").Methods(http.MethodPatch).HandlerFunc(WithJSON(editUser))
	accountsRouter.Path("/{id}").Methods(http.MethodDelete).HandlerFunc(WithJSON(deleteUser))
	accountsRouter.Path("/{id}/posts").Methods(http.MethodGet).HandlerFunc(WithJSON(getUserPosts))
	accountsRouter.Path("/{id}/ca").Methods(http.MethodGet).HandlerFunc(WithJSON(getUserCA))
	accountsRouter.NotFoundHandler = WithJSON(NotFoundHTTP)
}

func AccountsHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	accountsRouter.ServeHTTP(w, r)
}

func GetUserByEmail(email string) (*datastore.Key, *User, error) {
	query := datastore.NewQuery("User").
		FilterField("Email", "=", strings.ToLower(email)).
		Limit(1)
	ctx := context.Background()
	it := datastoreClient.Run(ctx, query)

	var user User
	key, err := it.Next(&user)
	if err == iterator.Done {
		return nil, nil, nil
	} else if err != nil {
		return nil, nil, err
	}

	return key, &user, nil
}

func GetUserById(id string) (*datastore.Key, *User, error) {
	key, err := datastore.DecodeKey(id)
	if err != nil {
		return nil, nil, err
	}

	var user User
	ctx := context.Background()
	if err = datastoreClient.Get(ctx, key, &user); err != nil {
		return nil, nil, err
	}

	return key, &user, nil
}

func GetUser(w http.ResponseWriter, out *json.Encoder, r *http.Request) (*datastore.Key, *User, bool) {
	id := mux.Vars(r)["id"]

	key, user, err := GetUserById(id)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		out.Encode(map[string]interface{}{
			"error": "failed to find user",
			"trace": err.Error(),
		})
		return nil, nil, false
	}

	return key, user, true
}

func GetUserKeyHash(user *User) (*string, error) {
	pemBlock, _ := pem.Decode([]byte(user.PublicKey))
	if pemBlock == nil {
		return nil, fmt.Errorf("invalid public key format")
	}

	hash := sha256.New()
	_, err := hash.Write(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}

	keyHash := base64.StdEncoding.EncodeToString(hash.Sum(nil))

	return &keyHash, nil
}

func createUser(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	var d struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"`
		Password  string `json:"password"`
	}
	if !ParseBody(&d, w, out, r) {
		return
	}

	if d.FirstName == "" {
		w.WriteHeader(http.StatusBadRequest)
		out.Encode(map[string]interface{}{
			"error": "first_name cannot be empty",
		})
		return
	} else if d.LastName == "" {
		w.WriteHeader(http.StatusBadRequest)
		out.Encode(map[string]interface{}{
			"error": "last_name cannot be empty",
		})
		return
	} else if d.Email == "" {
		w.WriteHeader(http.StatusBadRequest)
		out.Encode(map[string]interface{}{
			"error": "email cannot be empty",
		})
		return
	} else if d.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		out.Encode(map[string]interface{}{
			"error": "password cannot be empty",
		})
		return
	}

	_, existingUser, err := GetUserByEmail(d.Email)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to check email availability",
			"trace": err.Error(),
		})
		return
	} else if existingUser != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "email already taken",
			"trace": nil,
		})
		return
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to generate RSA key",
			"trace": err.Error(),
		})
		return
	}
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	pemBlock, err = x509.EncryptPEMBlock(rand.Reader, pemBlock.Type, pemBlock.Bytes, []byte(d.Password), x509.PEMCipherAES256)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to encrypt RSA key",
			"trace": err.Error(),
		})
		return
	}

	cert, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to derive public key",
			"trace": err.Error(),
		})
		return
	}

	user := User{
		FirstName:  d.FirstName,
		LastName:   d.LastName,
		Email:      strings.ToLower(d.Email),
		PrivateKey: string(pem.EncodeToMemory(pemBlock)),
		PublicKey: string(pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: cert,
		})),
		Moderator:        false,
		RegistrationDate: time.Now(),
	}

	ctx := context.Background()
	key, err := datastoreClient.Put(ctx, datastore.IncompleteKey("User", nil), &user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to save user",
			"trace": err.Error(),
		})
		return
	}

	keyHash, err := GetUserKeyHash(&user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to hash public RSA key",
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
		"key_hash":          keyHash,
		"moderator":         user.Moderator,
		"registration_date": user.RegistrationDate.Unix(),
	})
}

func getUser(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	key, user, ok := GetUser(w, out, r)
	if !ok {
		return
	}

	keyHash, err := GetUserKeyHash(user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to hash public RSA key",
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
		"key_hash":          keyHash,
		"moderator":         user.Moderator,
		"registration_date": user.RegistrationDate.Unix(),
	})
}

func editUser(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	var d struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"`
	}
	if !ParseBody(&d, w, out, r) {
		return
	}

	key, user, ok := GetUser(w, out, r)
	if !ok {
		return
	}

	// TODO: Check if authenticated as user or moderator

	if d.FirstName != "" && d.FirstName != user.FirstName {
		user.FirstName = d.FirstName
	}

	if d.LastName != "" && d.LastName != user.LastName {
		user.LastName = d.LastName
	}

	if d.Email != "" && !strings.EqualFold(d.Email, user.Email) {
		_, existingUser, err := GetUserByEmail(d.Email)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			out.Encode(map[string]interface{}{
				"error": "failed to check email availability",
				"trace": err.Error(),
			})
			return
		}
		if existingUser != nil {
			w.WriteHeader(http.StatusInternalServerError)
			out.Encode(map[string]interface{}{
				"error": "email already taken",
				"trace": nil,
			})
			return
		}

		user.Email = strings.ToLower(d.Email)
	}

	// TODO: Changing password

	ctx := context.Background()
	key, err := datastoreClient.Put(ctx, key, user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to save user",
			"trace": err.Error(),
		})
		return
	}

	keyHash, err := GetUserKeyHash(user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to hash public RSA key",
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
		"key_hash":          keyHash,
		"moderator":         user.Moderator,
		"registration_date": user.RegistrationDate.Unix(),
	})
}

func deleteUser(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	key, user, ok := GetUser(w, out, r)
	if !ok {
		return
	}

	// TODO: Check if authenticated as user or moderator

	ctx := context.Background()
	if err := datastoreClient.Delete(ctx, key); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to delete user",
			"trace": err.Error(),
		})
		return
	}

	keyHash, err := GetUserKeyHash(user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to hash public RSA key",
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
		"key_hash":          keyHash,
		"moderator":         user.Moderator,
		"registration_date": user.RegistrationDate.Unix(),
	})
}

func getUserPosts(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	// key, user, ok := GetUser(w, out, r)
	// if !ok {
	// 	return
	// }

	// TODO

	w.WriteHeader(http.StatusOK)
	out.Encode(map[string]interface{}{
		"posts": []interface{}{},
	})
}

func getUserCA(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	_, user, ok := GetUser(w, out, r)
	if !ok {
		return
	}

	w.WriteHeader(http.StatusOK)
	out.Encode(map[string]interface{}{
		"pem": user.PublicKey,
	})
}
