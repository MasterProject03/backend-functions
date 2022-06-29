package backendfunctions

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

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
	// TODO
}

func addSource(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	// TODO
}

func deleteSource(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	// TODO
}
