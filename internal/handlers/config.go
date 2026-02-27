package handlers

import "os"

const (
	defaultPort       = "8080"
	sessionCookieName = "sakura-jwt"
)

func serverPort() string {
	port := os.Getenv("PORT")
	if port == "" {
		return defaultPort
	}
	return port
}

func serverBaseURL() string {
	return "http://localhost:" + serverPort()
}
