package http

import (
	"encoding/json"
	"net/http"

	"github.com/Businge931/sba-user-accounts/internal/core/domain"
	"github.com/Businge931/sba-user-accounts/internal/core/ports"
)

type Handler struct {
	authService ports.AuthService
}

func NewHandler(authService ports.AuthService) *Handler {
	return &Handler{
		authService: authService,
	}
}

type registerRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// type resetPasswordRequest struct {
// 	Token       string `json:"token"`
// 	NewPassword string `json:"new_password"`
// }

// type changePasswordRequest struct {
// 	OldPassword string `json:"old_password"`
// 	NewPassword string `json:"new_password"`
// }

func (h *Handler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Email == "" || req.Password == "" || req.FirstName == "" || req.LastName == "" {
		http.Error(w, "All fields are required", http.StatusBadRequest)
		return
	}

	domainReq := domain.RegisterRequest{
		Email:     req.Email,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	}

	user, err := h.authService.Register(domainReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(user); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (h *Handler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Email == "" || req.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	domainReq := domain.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
	}

	token, err := h.authService.Login(domainReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{"token": token}); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// func (h *Handler) VerifyEmailHandler(w http.ResponseWriter, r *http.Request) {
// 	token := r.URL.Query().Get("token")
// 	if token == "" {
// 		http.Error(w, "Missing token", http.StatusBadRequest)
// 		return
// 	}

// 	if err := h.authService.VerifyEmail(token); err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	w.WriteHeader(http.StatusOK)
// }

// func (h *Handler) RequestPasswordResetHandler(w http.ResponseWriter, r *http.Request) {
// 	email := r.URL.Query().Get("email")
// 	if email == "" {
// 		http.Error(w, "Missing email", http.StatusBadRequest)
// 		return
// 	}

// 	if err := h.authService.RequestPasswordReset(email); err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	w.WriteHeader(http.StatusOK)
// }

// func (h *Handler) ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
// 	var req resetPasswordRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, "Invalid request body", http.StatusBadRequest)
// 		return
// 	}

// 	if err := h.authService.ResetPassword(req.Token, req.NewPassword); err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	w.WriteHeader(http.StatusOK)
// }

// func (h *Handler) ChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
// 	var req changePasswordRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, "Invalid request body", http.StatusBadRequest)
// 		return
// 	}

// 	// Get userID from context (set by authentication middleware)
// 	userID := r.Context().Value("userID").(string)

// 	if err := h.authService.ChangePassword(userID, req.OldPassword, req.NewPassword); err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	w.WriteHeader(http.StatusOK)
// }
