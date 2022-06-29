package backendfunctions

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

type Submission struct {
	Label           string
	PublisherId     string
	Title           string
	Content         string   `datastore:",noindex"`
	Sources         []string `datastore:",noindex"`
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
	// TODO
}

func queuePost(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	// TODO
}

func validatePost(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	// TODO
}
