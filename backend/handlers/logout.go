package handlers

import (
    "database/sql"
    "encoding/json"
    "log"
    "net/http"
    "strings"
)

func PostLogoutHandler(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        parts := strings.Split(authHeader, " ")
        if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
            http.Error(w, `{"error": "Token inválido en logout"}`, http.StatusBadRequest)
            return
        }
        tokenString := parts[1]

        err := InvalidateToken(db, tokenString)
        if err != nil {
            log.Printf("Error invalidando token durante logout: %v", err)
        }

        log.Printf("Logout procesado para token (hash: %s...)", HashToken(tokenString)[:10])
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{"message": "Logout exitoso"})
    }
}
