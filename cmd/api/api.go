package main

import (
	"net/http"
	"time"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	handlers "github.com/Businge931/sba-user-accounts/internal/adapters/primary/http"
	"github.com/Businge931/sba-user-accounts/internal/core/ports"
)

type Config struct {
	ServerPort   string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

type API struct {
	config  Config
	handler *handlers.Handler
}

func NewAPI(config Config, authService ports.AuthService) *API {
	return &API{
		config:  config,
		handler: handlers.NewHandler(authService),
	}
}

func (a *API) setupRoutes() http.Handler {
	router := mux.NewRouter()

	// add middlewares
	router.Use(mux.CORSMethodMiddleware(router))
	router.Use(loggingMiddleware)
	router.Use(recoveryMiddleware)

	v1 := router.PathPrefix("/v1").Subrouter()

	// Public routes
	v1.HandleFunc("/register", a.handler.RegisterHandler).Methods("POST")
	v1.HandleFunc("/login", a.handler.LoginHandler).Methods("POST")
	v1.HandleFunc("/verify-email", a.handler.VerifyEmailHandler).Methods("POST")
	v1.HandleFunc("/request-password-reset", a.handler.RequestPasswordResetHandler).Methods("POST")
	v1.HandleFunc("/reset-password", a.handler.ResetPasswordHandler).Methods("POST")

	// Protected routes
	v1.HandleFunc("/change-password", withAuth(a.handler.ChangePasswordHandler)).Methods("POST")

	return router
}

func (a *API) Start() error {
	server := &http.Server{
		Addr:         ":" + a.config.ServerPort,
		Handler:      a.setupRoutes(),
		ReadTimeout:  a.config.ReadTimeout,
		WriteTimeout: a.config.WriteTimeout,
	}

	return server.ListenAndServe()
}

// withAuth is a middleware that checks for a valid JWT token
func withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: Implement JWT token validation
		// Extract token from Authorization header
		// Validate token
		// Add userID to request context
		next(w, r)
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
		next.ServeHTTP(w, r)
	})
}

func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic: %+v", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
