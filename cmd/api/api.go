package main

import (
	"fmt"
	"net"

	grpcAdapter "github.com/Businge931/sba-user-accounts/internal/adapters/primary/grpc"
	"github.com/Businge931/sba-user-accounts/internal/core/ports"
	pb "github.com/Businge931/sba-user-accounts/proto"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type Config struct {
	ServerPort string
}

// API represents the gRPC server wrapper
type API struct {
	config     Config
	grpcServer *grpc.Server
	authServer *grpcAdapter.AuthServer
}

// NewAPI creates a new API instance with gRPC server setup
func NewAPI(config Config, authService ports.AuthService) *API {
	// Initialize gRPC server
	grpcServer := grpc.NewServer()
	
	// Create and register auth server
	authServer := &grpcAdapter.AuthServer{
		AuthService: authService,
	}
	pb.RegisterAuthServiceServer(grpcServer, authServer)
	
	// Register reflection service on gRPC server for debugging
	reflection.Register(grpcServer)
	
	return &API{
		config:     config,
		grpcServer: grpcServer,
		authServer: authServer,
	}
}

// Start begins listening for gRPC requests
func (a *API) Start() error {
	// Create TCP listener on configured port
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", a.config.ServerPort))
	if err != nil {
		return fmt.Errorf("failed to listen on port %s: %v", a.config.ServerPort, err)
	}
	
	log.Infof("Starting gRPC server on port %s", a.config.ServerPort)
	
	// Start serving gRPC requests
	return a.grpcServer.Serve(lis)
}

// func (a *API) setupRoutes() http.Handler {
// 	router := mux.NewRouter()

// 	// add middlewares
// 	router.Use(mux.CORSMethodMiddleware(router))
// 	router.Use(loggingMiddleware)
// 	router.Use(recoveryMiddleware)

// 	v1 := router.PathPrefix("/v1").Subrouter()

// 	// Public routes
// 	v1.HandleFunc("/register", a.handler.RegisterHandler).Methods("POST")
// 	v1.HandleFunc("/login", a.handler.LoginHandler).Methods("POST")
// 	v1.HandleFunc("/verify-email", a.handler.VerifyEmailHandler).Methods("POST")
// 	v1.HandleFunc("/request-password-reset", a.handler.RequestPasswordResetHandler).Methods("POST")
// 	v1.HandleFunc("/reset-password", a.handler.ResetPasswordHandler).Methods("POST")

// 	// Protected routes
// 	v1.HandleFunc("/change-password", withAuth(a.handler.ChangePasswordHandler)).Methods("POST")

// 	return router
// }

// // withAuth is a middleware that checks for a valid JWT token
// func withAuth(next http.HandlerFunc) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		// TODO: Implement JWT token validation
// 		// Extract token from Authorization header
// 		// Validate token
// 		// Add userID to request context
// 		next(w, r)
// 	}
// }

// func loggingMiddleware(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
// 		next.ServeHTTP(w, r)
// 	})
// }

// func recoveryMiddleware(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		defer func() {
// 			if err := recover(); err != nil {
// 				log.Printf("panic: %+v", err)
// 				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
// 			}
// 		}()
// 		next.ServeHTTP(w, r)
// 	})
// }
