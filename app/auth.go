package app

import (
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"net/http"
	u "../utils"
	"../models"
	"os"
	"context"
	"strings"
)

var JwtAuthentication = func(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		notAuth := []string{"/api/user/new", "/api/user/login"}
		requestPath := r.URL.Path

		for _, value := range notAuth{
			if value == requestPath{
				next.ServeHTTP(w, r)
				return
			}
		}

		response := make(map[string] interface{})

		tokenHeader := r.Header.Get("Authorization")

		if tokenHeader == ""{
			response = u.Message(false,"Missing auth token")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type","application/json")
			u.Respond(w,response)
			return
		}

		splitted := strings.Split(tokenHeader," ")
		if len(splitted) != 2{
			response = u.Message(false,"Invalid/Format auth token")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type","application/json")
			u.Respond(w,response)
			return
		}

		tokenpart := splitted[1]
		tk := &models.Token{}

		token,err := jwt.ParseWithClaims(tokenpart, tk, func(token *jwt.Token) (i interface{}, e error) {
				return []byte(os.Getenv("token_password")),nil
		})
		if err != nil { //Malformed token, returns with http code 403 as usual
			response = u.Message(false, "Malformed authentication token")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			u.Respond(w, response)
			return
		}

		if !token.Valid { //Token is invalid, maybe not signed on this server
			response = u.Message(false, "Token is not valid.")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			u.Respond(w, response)
			return
		}

		//Everything went well, proceed with the request and set the caller to the user retrieved from the parsed token
		fmt.Sprintf("User %s", tk.UserId) //Useful for monitoring
		ctx := context.WithValue(r.Context(), "user", tk.UserId)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r) //proceed in the middleware chain!
	})
}