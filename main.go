package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"sakura/internal/handlers"
)

func main() {
	r := http.NewServeMux()
	h := handlers.Handler{}

	r.HandleFunc("POST /signup", h.Signup)
	r.HandleFunc("POST /signin", h.Signin)
	r.HandleFunc("GET /protected", h.Protected)
	r.HandleFunc("GET /resource", h.Resource)
	r.HandleFunc("GET /authorize", h.Authorize)
	r.HandleFunc("POST /authorize/approve", h.AuthorizeApprove)

	r.HandleFunc("GET /token", h.Token)
	r.HandleFunc("POST /register-client", h.RegisterClient)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := http.Server{
		Handler: r,
		Addr:    ":" + port,
	}

	fmt.Printf("Starting server at :%s...\n", port)
	log.Fatal(server.ListenAndServe())
}
