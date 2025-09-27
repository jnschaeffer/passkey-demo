package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/jnschaeffer/passkey-demo/internal/storage"
	"github.com/jnschaeffer/passkey-demo/internal/webauthn"
)

//go:embed html/*
var htmlRootFS embed.FS

//go:embed js/*
var jsFS embed.FS

func main() {
	var (
		err        error
		storageSvc *storage.Service
		wauthSvc   *webauthn.Service
		htmlFS     fs.FS
	)

	storageSvc = storage.NewService()

	// TODO: Make these configurabl with env vars or similar.
	opts := []webauthn.Option{
		webauthn.WithRPDisplayName("Experimental Systems"),
		webauthn.WithRPID("localhost"),
		webauthn.WithRPOrigins([]string{"http://localhost"}),
		webauthn.WithConveyancePreference(protocol.PreferDirectAttestation),
		webauthn.WithStorage(storageSvc),
	}

	if wauthSvc, err = webauthn.NewService(opts...); err != nil {
		log.Fatal(err)
	}

	if htmlFS, err = fs.Sub(htmlRootFS, "html"); err != nil {
		log.Fatal(err)
	}

	http.Handle("GET /webauthn/{username}/register/start", http.HandlerFunc(wauthSvc.HandleRegistrationBegin))
	http.Handle("POST /webauthn/{username}/register/finish", http.HandlerFunc(wauthSvc.HandleRegistrationFinish))
	http.Handle("GET /webauthn/login/begin", http.HandlerFunc(wauthSvc.HandleAuthenticationBegin))
	http.Handle("POST /webauthn/login/finish", http.HandlerFunc(wauthSvc.HandleAuthenticationFinish))
	http.Handle("GET /{$}", http.FileServer(http.FS(htmlFS)))
	http.Handle("GET /js/", http.FileServer(http.FS(jsFS)))

	// Simple static webserver:
	log.Fatal(http.ListenAndServe(":80", nil))
}
