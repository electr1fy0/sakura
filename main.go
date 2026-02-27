package main

import (
	"fmt"
	"log"
	"net/http"
	"sakura/internal/handlers"

	"github.com/go-chi/chi/v5"
)

func main() {
	r := chi.NewRouter()
	h := handlers.Handler{}

	r.Post("/signup", h.Signup)
	r.Post("/signin", h.Signin)
	r.Get("/protected", (h.Protected))
	r.Get("/authorize", h.Authorize)

	r.Get("/token", h.Token)
	r.Post("/register-client", h.RegisterClient)

	server := http.Server{
		Handler: r,
		Addr:    ":8080",
	}

	fmt.Println("Starting server at :8080...")
	log.Fatal(server.ListenAndServe())
}
