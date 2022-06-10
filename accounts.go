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
	"net/http"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/gorilla/mux"
)

type User struct {
	FirstName        string
	LastName         string
	Email            string
	PrivateKey       []byte `datastore:",noindex"`
	KeyHash          string
	RegistrationDate time.Time
}

var accountsRouter *mux.Router

func init() {
	accountsRouter = mux.NewRouter().StrictSlash(false)
	accountsRouter.Path("/").Methods(http.MethodPost).HandlerFunc(WithJSON(createUser))
	accountsRouter.Path("/{id}").Methods(http.MethodGet).HandlerFunc(WithJSON(getUser))
	accountsRouter.Path("/{id}").Methods(http.MethodPatch).HandlerFunc(WithJSON(editUser))
	accountsRouter.Path("/{id}").Methods(http.MethodDelete).HandlerFunc(WithJSON(deleteUser))
	accountsRouter.NotFoundHandler = WithJSON(NotFoundHTTP)
}

func AccountsHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	accountsRouter.ServeHTTP(w, r)
}

func GetUser(w http.ResponseWriter, out *json.Encoder, r *http.Request) (*datastore.Key, *User, bool) {
	id := mux.Vars(r)["id"]

	ctx := context.Background()
	key, err := datastore.DecodeKey(id)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		out.Encode(map[string]string{
			"error": "failed to parse user ID",
			"trace": err.Error(),
		})
		return nil, nil, false
	}

	var user User
	if err = datastoreClient.Get(ctx, key, &user); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		out.Encode(map[string]string{
			"error": "failed to find user",
			"trace": err.Error(),
		})
		return nil, nil, false
	}

	return key, &user, true
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
		out.Encode(map[string]string{
			"error": "first_name cannot be empty",
		})
		return
	} else if d.LastName == "" {
		w.WriteHeader(http.StatusBadRequest)
		out.Encode(map[string]string{
			"error": "last_name cannot be empty",
		})
		return
	} else if d.Email == "" {
		w.WriteHeader(http.StatusBadRequest)
		out.Encode(map[string]string{
			"error": "email cannot be empty",
		})
		return
	} else if d.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		out.Encode(map[string]string{
			"error": "password cannot be empty",
		})
		return
	}

	// TODO: Check if Email is used

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]string{
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
		out.Encode(map[string]string{
			"error": "failed to encrypt RSA key",
			"trace": err.Error(),
		})
		return
	}

	cert, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]string{
			"error": "failed to derive public RSA key",
			"trace": err.Error(),
		})
		return
	}

	hash := sha256.New()
	_, err = hash.Write(cert)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]string{
			"error": "failed to hash public RSA key",
			"trace": err.Error(),
		})
		return
	}
	keyHash := base64.StdEncoding.EncodeToString(hash.Sum(nil))

	user := User{
		FirstName:        d.FirstName,
		LastName:         d.LastName,
		Email:            d.Email,
		PrivateKey:       pem.EncodeToMemory(pemBlock),
		KeyHash:          keyHash,
		RegistrationDate: time.Now(),
	}

	ctx := context.Background()
	key, err := datastoreClient.Put(ctx, datastore.IncompleteKey("User", nil), &user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]string{
			"error": "failed to save user",
			"trace": err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	out.Encode(map[string]string{
		"id":                key.Encode(),
		"first_name":        user.FirstName,
		"last_name":         user.LastName,
		"email":             user.Email,
		"key_hash":          user.KeyHash,
		"registration_date": user.RegistrationDate.String(),
	})
}

func getUser(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	key, user, ok := GetUser(w, out, r)
	if !ok {
		return
	}

	w.WriteHeader(http.StatusOK)
	out.Encode(map[string]string{
		"id":                key.Encode(),
		"first_name":        user.FirstName,
		"last_name":         user.LastName,
		"email":             user.Email,
		"key_hash":          user.KeyHash,
		"registration_date": user.RegistrationDate.String(),
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

	if d.FirstName != "" {
		user.FirstName = d.FirstName
	}

	if d.LastName != "" {
		user.LastName = d.LastName
	}

	if d.Email != "" {
		// TODO: Check if Email is used
		user.Email = d.Email
	}

	// TODO: Changing password

	ctx := context.Background()
	key, err := datastoreClient.Put(ctx, key, &user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]string{
			"error": "failed to save user",
			"trace": err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	out.Encode(map[string]string{
		"id":                key.Encode(),
		"first_name":        user.FirstName,
		"last_name":         user.LastName,
		"email":             user.Email,
		"key_hash":          user.KeyHash,
		"registration_date": user.RegistrationDate.String(),
	})
}

func deleteUser(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	key, user, ok := GetUser(w, out, r)
	if !ok {
		return
	}

	ctx := context.Background()
	if err := datastoreClient.Delete(ctx, key); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]string{
			"error": "failed to delete user",
			"trace": err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	out.Encode(map[string]string{
		"id":                key.Encode(),
		"first_name":        user.FirstName,
		"last_name":         user.LastName,
		"email":             user.Email,
		"key_hash":          user.KeyHash,
		"registration_date": user.RegistrationDate.String(),
	})
}
