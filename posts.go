package backendfunctions

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/gorilla/mux"
	"google.golang.org/api/iterator"
)

type Post struct {
	PrevBlock       string
	PublisherId     string
	Title           string
	Content         string   `datastore:",noindex"`
	Cover           string   `datastore:",noindex"`
	Sources         []string `datastore:",noindex"`
	Signature       string   `datastore:",noindex"`
	PublicationDate time.Time
}

var postsRouter *mux.Router

func init() {
	postsRouter = mux.NewRouter().StrictSlash(false)
	postsRouter.Path("/feed").Methods(http.MethodGet).HandlerFunc(WithJSON(getFeed))
	postsRouter.Path("/{id}").Methods(http.MethodGet).HandlerFunc(WithJSON(getPost))
	postsRouter.NotFoundHandler = WithJSON(NotFoundHTTP)
}

func PostsHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	postsRouter.ServeHTTP(w, r)
}

func GetPostById(id string) (*datastore.Key, *Post, error) {
	key, err := datastore.DecodeKey(id)
	if err != nil {
		return nil, nil, err
	}

	var post Post
	ctx := context.Background()
	if err = datastoreClient.Get(ctx, key, &post); err != nil {
		return nil, nil, err
	}

	return key, &post, nil
}

func GetLastPost() (*datastore.Key, *Post, error) {
	query := datastore.NewQuery("Post").
		Order("-PublicationDate").
		Limit(1)
	ctx := context.Background()
	it := datastoreClient.Run(ctx, query)

	var post Post
	key, err := it.Next(&post)
	if err == iterator.Done {
		return nil, nil, nil
	} else if err != nil {
		return nil, nil, err
	}

	return key, &post, nil
}

func getFeed(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	_, _, err := GetAuthUser(r, false)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		out.Encode(map[string]interface{}{
			"error": "unauthorized",
			"trace": err.Error(),
		})
		return
	}

	query := datastore.NewQuery("Post").
		Order("-PublicationDate").
		Limit(20)
	ctx := context.Background()
	it := datastoreClient.Run(ctx, query)

	feed := []map[string]interface{}{}
	for {
		var post Post
		key, err := it.Next(&post)
		if err == iterator.Done {
			break
		}
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			out.Encode(map[string]interface{}{
				"error": "failed to fetch feed post",
				"trace": err.Error(),
			})
			return
		}

		publisherKey, publisher, err := GetUserById(post.PublisherId)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			out.Encode(map[string]interface{}{
				"error": "failed to fetch feed post's publisher",
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

		// TODO: Parse HTML and extract first img tag for preview]
		// https://stackoverflow.com/a/38855264

		feed = append(feed, map[string]interface{}{
			"id":         key.Encode(),
			"prev_block": post.PrevBlock,
			"publisher": map[string]interface{}{
				"id":                publisherKey.Encode(),
				"first_name":        publisher.FirstName,
				"last_name":         publisher.LastName,
				"email":             publisher.Email,
				"key_hash":          keyHash,
				"moderator":         publisher.Moderator,
				"registration_date": publisher.RegistrationDate.Unix(),
			},
			"title":            post.Title,
			"cover":            post.Cover,
			"sources":          post.Sources,
			"signature":        post.Signature,
			"publication_date": post.PublicationDate.Unix(),
		})
	}

	w.WriteHeader(http.StatusOK)
	out.Encode(feed)
}

func getPost(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	id := mux.Vars(r)["id"]

	key, post, err := GetPostById(id)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		out.Encode(map[string]interface{}{
			"error": "failed to find post",
			"trace": err.Error(),
		})
		return
	}

	publisherKey, publisher, err := GetUserById(post.PublisherId)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to fetch feed post's publisher",
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

	w.WriteHeader(http.StatusOK)
	out.Encode(map[string]interface{}{
		"id":         key.Encode(),
		"prev_block": post.PrevBlock,
		"publisher": map[string]interface{}{
			"id":                publisherKey.Encode(),
			"first_name":        publisher.FirstName,
			"last_name":         publisher.LastName,
			"email":             publisher.Email,
			"key_hash":          keyHash,
			"moderator":         publisher.Moderator,
			"registration_date": publisher.RegistrationDate.Unix(),
		},
		"title":            post.Title,
		"content":          post.Content,
		"cover":            post.Cover,
		"sources":          post.Sources,
		"signature":        post.Signature,
		"publication_date": post.PublicationDate.Unix(),
	})
}
