package output

import (
	"crypto/tls"
	"fmt"
	"time"
)

// FeedFunc is how output happens.
type FeedFunc func(interface{}) error

// HeartbeatFunc lets remote servers know that you're still alive and kicking
type HeartbeatFunc func() error

// NewHTTPSOutput contextualizes output for a configured server
func NewHTTPSOutput(fqdn string, tlsConfig *tls.Config) (out FeedFunc, err error) {
	out = func(interface{}) error {
		_ = fqdn
		return nil
	}
	return
}

// NewHTTPSHeartbeat contextualizes a heartbeat for a configured server
func NewHTTPSHeartbeat(fqdn string, tlsConfig *tls.Config) (lubdub HeartbeatFunc, err error) {
	lubdub = func() error {
		return nil
	}
	return
}

// StdoutOutput barfs events to stdout
func StdoutOutput(event interface{}) error {
	fmt.Printf("%s: %+v\n", time.Now().Format(time.RFC3339), event)
	return nil
}

// NoOpHeartbeat returns nil all of the time
func NoOpHeartbeat() error {
	return nil
}
