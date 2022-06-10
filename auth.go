package backendfunctions

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

var authRouter *mux.Router

func init() {
	authRouter = mux.NewRouter().StrictSlash(false)
	authRouter.Path("/login").Methods(http.MethodPost).HandlerFunc(WithJSON(login))
	authRouter.Path("/certificate").Methods(http.MethodGet).HandlerFunc(WithJSON(getAuthCertificate))
	authRouter.Path("/token/{token}").Methods(http.MethodGet).HandlerFunc(WithJSON(checkAuth))
	authRouter.Path("/token/{token}/refresh").Methods(http.MethodPost).HandlerFunc(WithJSON(refreshAuth))
	authRouter.NotFoundHandler = WithJSON(NotFoundHTTP)
}

func AuthHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	authRouter.ServeHTTP(w, r)
}

func login(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	// TODO
}

func getAuthCertificate(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	// TODO
}

func checkAuth(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	// TODO
}

func refreshAuth(w http.ResponseWriter, out *json.Encoder, r *http.Request) {
	// TODO
}
