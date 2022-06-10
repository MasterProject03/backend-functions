package backendfunctions

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"cloud.google.com/go/datastore"
	"github.com/GoogleCloudPlatform/functions-framework-go/functions"
)

type JSONHandler func(http.ResponseWriter, *json.Encoder, *http.Request)

var datastoreClient *datastore.Client

func init() {
	functions.HTTP("AccountsHTTP", AccountsHTTP)
	functions.HTTP("AuthHTTP", AuthHTTP)
	functions.HTTP("SourcesHTTP", SourcesHTTP)
	functions.HTTP("PostsHTTP", PostsHTTP)
	functions.HTTP("SubmissionHTTP", SubmissionHTTP)

	ctx := context.Background()
	var err error
	datastoreClient, err = datastore.NewClient(ctx, "mackee-news")
	if err != nil {
		log.Fatal("failed to connect to datastore: %w", err)
	}
}

func WithJSON(handler JSONHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handler(w, json.NewEncoder(w), r)
	}
}

func WithMethods(handlers map[string]JSONHandler) JSONHandler {
	return func(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
		if handler, ok := handlers[r.Method]; ok {
			handler(w, out, r)
		} else {
			NotFoundHTTP(w, out, r)
		}
	}
}

func NotFoundHTTP(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	out.Encode(map[string]string{
		"error": fmt.Sprintf("endpoint %s %s not found", r.Method, r.URL.Path),
	})
}

func ParseBody(d interface{}, w http.ResponseWriter, out *json.Encoder, r *http.Request) bool {
	if err := json.NewDecoder(r.Body).Decode(d); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		out.Encode(map[string]string{
			"error": "failed to parse body",
			"trace": err.Error(),
		})
		return false
	}

	return true
}
