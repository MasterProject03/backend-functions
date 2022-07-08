package backendfunctions

import (
	"context"
	"encoding/json"
	"net/http"

	"cloud.google.com/go/datastore"
	"github.com/gorilla/mux"
	"google.golang.org/api/iterator"
)

type Source struct {
	Name    string
	Domains []string
}

var sourcesRouter *mux.Router

func init() {
	sourcesRouter = mux.NewRouter().StrictSlash(false)
	sourcesRouter.Path("/").Methods(http.MethodGet).HandlerFunc(WithJSON(listSources))
	sourcesRouter.Path("/").Methods(http.MethodPost).HandlerFunc(WithJSON(addSource))
	sourcesRouter.Path("/{id}").Methods(http.MethodDelete).HandlerFunc(WithJSON(deleteSource))
	sourcesRouter.NotFoundHandler = WithJSON(NotFoundHTTP)
}

func SourcesHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	sourcesRouter.ServeHTTP(w, r)
}

func listSources(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	query := datastore.NewQuery("Source")
	ctx := context.Background()
	it := datastoreClient.Run(ctx, query)
	sources := []map[string]interface{}{}
	for {
		var source Source
		key, err := it.Next(&source)
		if err == iterator.Done {
			break
		} else if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			out.Encode(map[string]interface{}{
				"error": "failed to fetch source",
				"trace": err.Error(),
			})
			return
		}

		sources = append(sources, map[string]interface{}{
			"id":      key.Encode(),
			"name":    source.Name,
			"domains": source.Domains,
		})
	}

	w.WriteHeader(http.StatusOK)
	out.Encode(map[string]interface{}{
		"sources": sources,
	})
}

func addSource(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	var d struct {
		Name    string   `json:"name"`
		Domains []string `json:"domains"`
	}
	if !ParseBody(&d, w, out, r) {
		return
	}

	if d.Name == "" {
		w.WriteHeader(http.StatusBadRequest)
		out.Encode(map[string]interface{}{
			"error": "name cannot be empty",
			"trace": nil,
		})
		return
	} else if len(d.Domains) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		out.Encode(map[string]interface{}{
			"error": "domains cannot be empty",
			"trace": nil,
		})
		return
	}

	_, user, err := GetAuthUser(r, false)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		out.Encode(map[string]interface{}{
			"error": "not authenticated",
			"trace": err.Error(),
		})
		return
	}

	if !user.Moderator {
		w.WriteHeader(http.StatusUnauthorized)
		out.Encode(map[string]interface{}{
			"error": "insufficient permissions",
			"trace": nil,
		})
		return
	}

	source := Source{
		Name:    d.Name,
		Domains: d.Domains,
	}

	ctx := context.Background()
	key, err := datastoreClient.Put(ctx, datastore.IncompleteKey("Source", nil), &user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to save user",
			"trace": err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	out.Encode(map[string]interface{}{
		"id":      key.Encode(),
		"name":    source.Name,
		"domains": source.Domains,
	})
}

func deleteSource(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	id := mux.Vars(r)["id"]

	key, err := datastore.DecodeKey(id)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		out.Encode(map[string]interface{}{
			"error": "invalid source ID",
			"trace": err.Error(),
		})
		return
	}

	var source Source
	ctx := context.Background()
	if err = datastoreClient.Get(ctx, key, &source); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		out.Encode(map[string]interface{}{
			"error": "failed to find source",
			"trace": err.Error(),
		})
		return
	}

	_, user, err := GetAuthUser(r, false)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		out.Encode(map[string]interface{}{
			"error": "not authenticated",
			"trace": err.Error(),
		})
		return
	}

	if !user.Moderator {
		w.WriteHeader(http.StatusUnauthorized)
		out.Encode(map[string]interface{}{
			"error": "insufficient permissions",
			"trace": nil,
		})
		return
	}

	if err := datastoreClient.Delete(ctx, key); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		out.Encode(map[string]interface{}{
			"error": "failed to delete user",
			"trace": err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	out.Encode(map[string]interface{}{
		"id":      key.Encode(),
		"name":    source.Name,
		"domains": source.Domains,
	})
}
