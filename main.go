package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/phayes/freeport"
	"github.com/skratchdot/open-golang/open"
	"golang.org/x/oauth2"
)

var version = "1.0.0"
var alphabet = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {
	var issuerURL = flag.String("issuer", "", "Issuer URL")
	var clientID = flag.String("client-id", "", "Client ID")
	var clientSecret = flag.String("client-secret", "", "Client Secret")
	var versionMode = flag.Bool("version", false, "Show version")
	flag.Parse()

	if *versionMode {
		fmt.Printf("kubeoidc v%s\n", version)
		return
	}

	port, err := freeport.GetFreePort()
	if err != nil {
		log.Fatal(err)
	}

	server, err := newServer(
		*issuerURL,
		*clientID,
		*clientSecret,
		fmt.Sprintf("http://localhost:%d/callback", port),
	)

	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/callback", server.handleCallback)

	listen := fmt.Sprintf("localhost:%d", port)
	log.Printf("INFO: Listening %s", listen)
	go func() {
		log.Fatal(http.ListenAndServe(listen, nil))
	}()

	open.Start(server.authURL())
	server.wait()
}

type server struct {
	oauth2   oauth2.Config
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	waitCh   chan struct{}

	issuerURL    string
	clientID     string
	clientSecret string
	redirectURL  string
	state        string
}

func newState() string {
	b := make([]rune, 64)
	for i := range b {
		b[i] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(b)
}

func newServer(issuerURL, clientID, clientSecret, redirectURL string) (*server, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, err
	}

	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups", "offline_access"},
	}

	idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	return &server{
		provider:     provider,
		oauth2:       oauth2Config,
		verifier:     idTokenVerifier,
		issuerURL:    issuerURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		state:        newState(),
		waitCh:       make(chan struct{}),
	}, nil
}

func (s *server) authURL() string {
	return s.oauth2.AuthCodeURL(s.state)
}

func (s *server) handleCallback(w http.ResponseWriter, r *http.Request) {
	err := s._handleCallback(w, r)
	if err != nil {
		log.Printf("ERROR: %s", err)
		w.WriteHeader(500)
	}

	s.waitCh <- struct{}{}
}

func (s *server) _handleCallback(w http.ResponseWriter, r *http.Request) error {
	state := r.URL.Query().Get("state")
	if s.state != state {
		return errors.New("state paremeter mismatch")
	}

	oauth2Token, err := s.oauth2.Exchange(context.Background(), r.URL.Query().Get("code"))
	if err != nil {
		return err
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return errors.New("id_token is not a string")
	}

	idToken, err := s.verifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		return err
	}

	var c json.RawMessage
	idToken.Claims(&c)
	log.Printf("%s", c)

	var claims struct {
		Email string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return err
	}

	fmt.Printf(`---
# Add the following to ~/.kube/config
users:
- name: '%s'
  user:
    auth-provider:
      config:
        client-id: '%s'
        client-secret: '%s'
        id-token: '%s'
        idp-issuer-url: '%s'
        refresh-token: '%s'
      name: oidc
`, claims.Email, s.clientID, s.clientSecret, rawIDToken, s.issuerURL, oauth2Token.RefreshToken)

	w.WriteHeader(200)
	fmt.Fprint(w, "Done. Please go back to the terminal.\n")

	return nil
}

func (s *server) wait() {
	<-s.waitCh
	time.Sleep(time.Second)
}
