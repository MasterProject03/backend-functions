package backendfunctions

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/gorilla/mux"
	"google.golang.org/api/iterator"
)

type Submission struct {
	PublisherId     string
	Title           string
	Content         string   `datastore:",noindex"`
	Cover           string   `datastore:",noindex"`
	Sources         []string `datastore:",noindex"`
	Signature       string   `datastore:",noindex"`
	PublicationDate time.Time
}

var submissionRouter *mux.Router

func init() {
	submissionRouter = mux.NewRouter().StrictSlash(false)
	submissionRouter.Path("/").Methods(http.MethodGet).HandlerFunc(WithJSON(getQueue))
	submissionRouter.Path("/").Methods(http.MethodPost).HandlerFunc(WithJSON(queuePost))
	submissionRouter.Path("/{id}").Methods(http.MethodPut).HandlerFunc(WithJSON(validatePost))
	submissionRouter.NotFoundHandler = WithJSON(NotFoundHTTP)
}

func SubmissionHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	submissionRouter.ServeHTTP(w, r)
}

func getQueue(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	query := datastore.NewQuery("Submission").
		Order("PublicationDate")
	ctx := context.Background()
	it := datastoreClient.Run(ctx, query)

	queue := []map[string]interface{}{}
	for {
		var submission Submission
		key, err := it.Next(&submission)
		if err == iterator.Done {
			break
		}
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			out.Encode(map[string]interface{}{
				"error": "failed to fetch queue submission",
				"trace": err.Error(),
			})
			return
		}

		publisherKey, publisher, err := GetUserById(submission.PublisherId)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			out.Encode(map[string]interface{}{
				"error": "failed to fetch queue submission's publisher",
				"trace": err.Error(),
			})
			return
		}

		keyHash, err := GetUserKeyHash(publisher)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			out.Encode(map[string]interface{}{
				"error": "failed to hash public RSA key",
				"trace": err.Error(),
			})
			return
		}

		queue = append(queue, map[string]interface{}{
			"id": key.Encode(),
			"publisher": map[string]interface{}{
				"id":                publisherKey.Encode(),
				"first_name":        publisher.FirstName,
				"last_name":         publisher.LastName,
				"email":             publisher.Email,
				"key_hash":          keyHash,
				"moderator":         publisher.Moderator,
				"registration_date": publisher.RegistrationDate.Unix(),
			},
			"title":            submission.Title,
			"content":          submission.Content,
			"cover":            submission.Cover,
			"sources":          submission.Sources,
			"signature":        submission.Signature,
			"publication_date": submission.PublicationDate.Unix(),
		})
	}

	w.WriteHeader(http.StatusOK)
	out.Encode(queue)
}

func queuePost(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	var d struct {
		Title    string   `json:"title"`
		Content  string   `json:"content"`
		Cover    string   `json:"cover"`
		Sources  []string `json:"sources"`
		Password string   `json:"password"`
	}
	if !ParseBody(&d, w, out, r) {
		return
	}

	if d.Title == "" {
		w.WriteHeader(http.StatusBadRequest)
		out.Encode(map[string]interface{}{
			"error": "title cannot be empty",
		})
		return
	} else if d.Content == "" {
		w.WriteHeader(http.StatusBadRequest)
		out.Encode(map[string]interface{}{
			"error": "content cannot be empty",
		})
		return
	} else if d.Cover == "" {
		w.WriteHeader(http.StatusBadRequest)
		out.Encode(map[string]interface{}{
			"error": "cover cannot be empty",
		})
		return
	} else if len(d.Sources) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		out.Encode(map[string]interface{}{
			"error": "sources cannot be empty",
		})
		return
	} else if d.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		out.Encode(map[string]interface{}{
			"error": "password cannot be empty",
		})
		return
	}

	key, user, err := GetAuthUser(r, true)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		out.Encode(map[string]interface{}{
			"error": "unauthorized",
			"trace": err.Error(),
		})
		return
	}

	pemBlock, _ := pem.Decode([]byte(user.PrivateKey))
	if pemBlock == nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "incorrect password",
			"trace": "invalid private key format",
		})
		return
	}

	pemBytes, err := x509.DecryptPEMBlock(pemBlock, []byte(d.Password))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "incorrect password",
			"trace": err.Error(),
		})
		return
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(pemBytes)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to parse private key",
			"trace": err.Error(),
		})
		return
	}

	submission := Submission{
		PublisherId:     key.Encode(),
		Title:           d.Title,
		Content:         d.Content,
		Cover:           d.Cover,
		Sources:         d.Sources,
		PublicationDate: time.Now(),
	}

	submissionJson, err := json.Marshal(map[string]interface{}{
		"publisher_id":     submission.PublisherId,
		"title":            submission.Title,
		"content":          submission.Content,
		"cover":            submission.Cover,
		"sources":          submission.Sources,
		"signature":        submission.Signature,
		"publication_date": submission.PublicationDate.Unix(),
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to format submission for signature",
			"trace": err.Error(),
		})
		return
	}

	msgHash := sha256.New()
	_, err = msgHash.Write(submissionJson)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to hash submission for signature",
			"trace": err.Error(),
		})
		return
	}
	msgHashSum := msgHash.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, msgHashSum, nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to sign submission",
			"trace": err.Error(),
		})
		return
	}

	submission.Signature = base64.StdEncoding.EncodeToString(signature)

	ctx := context.Background()
	submissionKey, err := datastoreClient.Put(ctx, datastore.IncompleteKey("Submission", nil), &submission)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to save submission",
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
		"id": submissionKey.Encode(),
		"publisher": map[string]interface{}{
			"id":                key.Encode(),
			"first_name":        user.FirstName,
			"last_name":         user.LastName,
			"email":             user.Email,
			"key_hash":          keyHash,
			"moderator":         user.Moderator,
			"registration_date": user.RegistrationDate.Unix(),
		},
		"title":            submission.Title,
		"content":          submission.Content,
		"cover":            submission.Cover,
		"sources":          submission.Sources,
		"signature":        submission.Signature,
		"publication_date": submission.PublicationDate.Unix(),
	})

	// TODO: Validate with AI

	go func() {
		time.Sleep(15 * time.Second)

		ctx := context.Background()
		err := datastoreClient.Delete(ctx, submissionKey)
		if err != nil {
			fmt.Printf("failed to delete submission: %s", err.Error())
			return
		}

		lastPost, _, err := GetLastPost()
		if err != nil {
			fmt.Printf("failed to get last block: %s", err.Error())
			return
		}

		prevBlock := ""
		if lastPost != nil {
			prevBlock = lastPost.Encode()
		}

		post := Post{
			PrevBlock:       prevBlock,
			PublisherId:     submission.PublisherId,
			Title:           submission.Title,
			Content:         submission.Content,
			Cover:           submission.Cover,
			Sources:         submission.Sources,
			Signature:       submission.Signature,
			PublicationDate: submission.PublicationDate,
		}

		_, err = datastoreClient.Put(ctx, datastore.IncompleteKey("Post", nil), &post)
		if err != nil {
			fmt.Printf("failed to save post: %s", err.Error())
			return
		}
	}()
}

func validatePost(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	// TODO
}
