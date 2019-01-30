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
	"os/exec"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/phayes/freeport"
	"github.com/skratchdot/open-golang/open"
	"golang.org/x/oauth2"
)

var version = "1.1.0"
var alphabet = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {
	var issuerURL = flag.String("issuer", "", "Issuer URL")
	var clientID = flag.String("client-id", "", "Client ID")
	var clientSecret = flag.String("client-secret", "", "Client Secret")
	var credentialName = flag.String("set-credentials", "", "If name of credentials is set, kubeoidc configures credentials by executing kubectl")
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
		*credentialName,
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

	url := server.authURL()
	log.Printf("INFO: Opening %s", url)
	open.Start(url)
	server.wait()
}

type server struct {
	oauth2   oauth2.Config
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	waitCh   chan struct{}
	isGoogle bool

	issuerURL      string
	clientID       string
	clientSecret   string
	redirectURL    string
	state          string
	credentialName string
}

func newState() string {
	b := make([]rune, 64)
	for i := range b {
		b[i] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(b)
}

func newServer(issuerURL, clientID, clientSecret, redirectURL, credentialName string) (*server, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, err
	}
	isGoogle := strings.Index(issuerURL, "https://accounts.google.com") == 0
	scopes := []string{oidc.ScopeOpenID, "profile", "email"}

	// google does not tolerate "groups" or "offline_access"
	// they have their own peoplev1 specific scopes for obtaining groups
	// and the offline_access needs to be a separate query param
	// https://developers.google.com/identity/protocols/OpenIDConnect#scope-param
	if !isGoogle {
		scopes = append(scopes, "groups", "offline_access")
	}
	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	return &server{
		provider:       provider,
		oauth2:         oauth2Config,
		verifier:       idTokenVerifier,
		isGoogle:       isGoogle,
		issuerURL:      issuerURL,
		clientID:       clientID,
		clientSecret:   clientSecret,
		redirectURL:    redirectURL,
		credentialName: credentialName,
		state:          newState(),
		waitCh:         make(chan struct{}),
	}, nil
}

func (s *server) authURL() string {
	opts := make([]oauth2.AuthCodeOption, 0)
	if s.isGoogle {
		opts = append(opts, oauth2.AccessTypeOffline)
	}
	return s.oauth2.AuthCodeURL(s.state, opts...)
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

	if s.credentialName == "" {
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
	} else {
		err := exec.Command("kubectl", "config", "set-credentials", s.credentialName,
			"--auth-provider=oidc",
			fmt.Sprintf("--auth-provider-arg=client-id=%s", s.clientID),
			fmt.Sprintf("--auth-provider-arg=client-secret=%s", s.clientSecret),
			fmt.Sprintf("--auth-provider-arg=id-token=%s", rawIDToken),
			fmt.Sprintf("--auth-provider-arg=idp-issuer-url=%s", s.issuerURL),
			fmt.Sprintf("--auth-provider-arg=refresh-token=%s", oauth2Token.RefreshToken),
		).Run()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Executed `kubectl config set-credentials %s ...`", s.credentialName)
	}

	w.WriteHeader(200)
	fmt.Fprint(w, "Done. Please go back to the terminal.\n")

	return nil
}

func (s *server) wait() {
	<-s.waitCh
	time.Sleep(time.Second)
}
