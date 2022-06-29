package backendfunctions

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

type Post struct {
	Label           string
	PublisherId     string
	Title           string
	Content         string   `datastore:",noindex"`
	Sources         []string `datastore:",noindex"`
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

func getFeed(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	// TODO
}

func getPost(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	// TODO
}
