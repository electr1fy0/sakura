package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"sakura/internal/handlers"

	"github.com/go-chi/chi/v5"
)

func main() {
	r := chi.NewRouter()
	h := handlers.Handler{}

	r.Post("/signup", h.Signup)
	r.Post("/signin", h.Signin)
	r.Get("/protected", (h.Protected))
	r.Get("/resource", h.Resource)
	r.Get("/authorize", h.Authorize)
	r.Post("/authorize/approve", h.AuthorizeApprove)

	r.Get("/token", h.Token)
	r.Post("/register-client", h.RegisterClient)

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
