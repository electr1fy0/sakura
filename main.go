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
	r.Get("/protected", handlers.VerifySession((h.Protected)))
	r.Get("/authorize", handlers.VerifySession((h.Authorize)))
	r.Get("/token", h.Token)

	server := http.Server{
		Handler: r,
		Addr:    ":8080",
	}

	fmt.Println("Starting server at :8080...")
	log.Fatal(server.ListenAndServe())
}
