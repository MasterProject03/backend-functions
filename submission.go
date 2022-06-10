package backendfunctions

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

var submissionRouter *mux.Router

func init() {
	submissionRouter = mux.NewRouter().StrictSlash(false)
	submissionRouter.Path("/").Methods(http.MethodPost).HandlerFunc(WithJSON(queuePost))
	submissionRouter.Path("/{id}").Methods(http.MethodPut).HandlerFunc(WithJSON(validatePost))
	submissionRouter.NotFoundHandler = WithJSON(NotFoundHTTP)
}

func SubmissionHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	submissionRouter.ServeHTTP(w, r)
}

func queuePost(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	// TODO
}

func validatePost(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	// TODO
}
