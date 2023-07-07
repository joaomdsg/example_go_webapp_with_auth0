package main

import (
	"context"
	"encoding/gob"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

var (
	auth0Domain       string
	auth0ClientID     string
	auth0ClientSecret string
	auth0CallbackURL  string
)

var (
	// auth0 config
	auth0Config *oauth2.Config
	// Sessions store
	store *sessions.CookieStore
)

func main() {

	// load .env variables
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	auth0Domain = os.Getenv("AUTH0_DOMAIN")
	auth0ClientID = os.Getenv("AUTH0_CLIENT_ID")
	auth0ClientSecret = os.Getenv("AUTH0_CLIENT_SECRET")
	auth0CallbackURL = os.Getenv("AUTH0_CALLBACK_URL")

	// define auth0 config
	auth0Config = &oauth2.Config{
		RedirectURL:  auth0CallbackURL,
		ClientID:     auth0ClientID,
		ClientSecret: auth0ClientSecret,
		Scopes:       []string{"openid", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("https://%s/authorize", auth0Domain),
			TokenURL: fmt.Sprintf("https://%s/oauth/token", auth0Domain),
		},
	}

	// setup store w/ 1 hour expiration
	store = sessions.NewCookieStore([]byte("a-very-secret-key"))
	store.MaxAge(3600)
	gob.Register(time.Time{})

	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/callback", handleCallback)

	log.Fatal(http.ListenAndServe(":3000", nil))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "auth-session")
	// Check the session expiry time
	if expiry, ok := session.Values["expiry"].(time.Time); !ok || time.Now().After(expiry) {
		// Session has expired
		session.Values["id_token"] = ""
		session.Values["access_token"] = ""
		session.Options.MaxAge = -1
		session.Save(r, w)
	}

	idToken, ok := session.Values["id_token"].(string)
	if !ok || idToken == "" {
		// Not signed in
		w.Write([]byte(`<a href="/login">Login</a>`))
		return
	}

	// Parse the ID token to get the user info
	token, _, err := new(jwt.Parser).ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		log.Println("reached here! " + err.Error())
	}
	claims, _ := token.Claims.(jwt.MapClaims)
	name := claims["name"].(string)
	picture := claims["picture"].(string)

	// Signed in, display user info and logout button
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<img src="%s"/><br/>Hello, %s!<br/><a href="/logout">Logout</a>`, picture, name)
}
func handleLogin(w http.ResponseWriter, r *http.Request) {
	url := auth0Config.AuthCodeURL("state", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	token, err := auth0Config.Exchange(context.TODO(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Save the token to session
	session, _ := store.Get(r, "auth-session")
	session.Values["access_token"] = token.AccessToken
	session.Values["id_token"] = token.Extra("id_token").(string) // Save the ID token
	session.Values["expiry"] = time.Now().Add(1 * time.Hour)      // Set the expiry time to 1 hour from now
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "auth-session")
	session.Values["id_token"] = ""
	session.Values["access_token"] = ""
	session.Options.MaxAge = -1
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
