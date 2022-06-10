package backendfunctions

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

var postsRouter *mux.Router

func init() {
	postsRouter = mux.NewRouter().StrictSlash(false)
	postsRouter.Path("/").Methods(http.MethodPost).HandlerFunc(WithJSON(createPost))
	postsRouter.Path("/{id}").Methods(http.MethodGet).HandlerFunc(WithJSON(getPost))
	postsRouter.Path("/{id}").Methods(http.MethodDelete).HandlerFunc(WithJSON(revokePost))
	postsRouter.NotFoundHandler = WithJSON(NotFoundHTTP)
}

func PostsHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	postsRouter.ServeHTTP(w, r)
}

func createPost(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	// TODO
}

func getPost(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	// TODO
}

func revokePost(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	// TODO
}
