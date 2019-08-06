package db

import (
	"time"

	"github.com/cayleygraph/cayley/graph"
	"github.com/cayleygraph/cayley/quad"
)

// UpdateHeartbeat does... well...
func UpdateHeartbeat(store *graph.Handle, hostname string, ts time.Time) error {
	return store.AddQuad(quad.Make(hostname, "last seen", ts, "lastSeen"))
}
