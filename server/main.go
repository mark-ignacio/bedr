package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/mark-ignacio/bedr/server/internal/handlers"
)

var (
	tlsKeyPath        string
	tlsCertPath       string
	tlsClientCertPath string
	listenAddr        string
)

func main() {
	var (
		err error
		ctx = context.Background()
	)
	flag.StringVar(&tlsKeyPath, "key", "/etc/bedr/server.key", "TLS key path")
	flag.StringVar(&tlsCertPath, "cert", "/etc/bedr/server.pem", "TLS certificate path")
	flag.StringVar(&tlsClientCertPath, "client-cert", "/etc/bedr/client.pem", "The One client certificate")
	flag.StringVar(&listenAddr, "listen", ":6789", "listen address (e.g. ':https', '[::1]:443' ")
	flag.Parse()
	if _, err := os.Stat(tlsKeyPath); err != nil {
		log.Fatalf("error getting TLS key: %+v", err)
	}
	if _, err := os.Stat(tlsCertPath); err != nil {
		log.Fatalf("error getting TLS certificate: %+v", err)
	}
	clientCA, err := ioutil.ReadFile(tlsClientCertPath)
	if err != nil {
		log.Fatalf("error getting client certificate: %+v", err)
	}
	clientCAPool := x509.NewCertPool()
	clientCAPool.AppendCertsFromPEM(clientCA)
	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCAPool,
	}
	s := &http.Server{
		Addr:      listenAddr,
		TLSConfig: tlsConfig,
		Handler:   handlers.GenHTTPHandler(ctx),
	}
	err = s.ListenAndServeTLS(tlsCertPath, tlsKeyPath)
	if err != nil {
		log.Fatalf("unable to start server: %+v", err)
	}
}
