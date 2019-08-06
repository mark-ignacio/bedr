package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/cayleygraph/cayley/graph"
	"github.com/mark-ignacio/bedr/common"
	"github.com/mark-ignacio/bedr/server/internal/db"
)

// GenHTTPHandler generates a handler connected to some sort of DB service thing
func GenHTTPHandler(ctx context.Context) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/sup", handleSup)
	return mux
}

func handleSup(w http.ResponseWriter, req *http.Request) {
	// uuid := resolveHost(req.TLS.PeerCertificates)
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var (
		sup     common.SupMessage
		store   *graph.Handle
		decoder = json.NewDecoder(req.Body)
	)
	err := decoder.Decode(&sup)
	defer req.Body.Close()
	if err != nil {
		switch err.Error() {
		case "EOF":
			w.WriteHeader(http.StatusBadRequest)
			break
		default:
			w.WriteHeader(500)
		}
		// TODO: return a 4xx where appropriate
		log.Printf("unable to decode sup payload: %+v", err)
		return
	}
	switch sup.Op {
	case common.OpHeartbeat:
		err = db.UpdateHeartbeat(store, sup.Facts.Hostname, time.Now())
	}
	if err != nil {
		log.Printf("error handling request: %+v", err)
	}
}
