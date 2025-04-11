package handlers

import (
    "database/sql"
    "encoding/json"
    "log"
    "net/http"

    "myapp/backend/models"
    "golang.org/x/crypto/bcrypt"
)

func PostLoginHandler(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var creds models.LoginRequest
        if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
            http.Error(w, `{"error": "Cuerpo de solicitud inválido"}`, http.StatusBadRequest)
            return
        }
        if creds.Username == "" || creds.Password == "" {
            http.Error(w, `{"error": "Usuario y contraseña requeridos"}`, http.StatusBadRequest)
            return
        }

        var storedHash string
        var userID int
        err := db.QueryRow("SELECT id, password_hash FROM users WHERE username = ?", creds.Username).Scan(&userID, &storedHash)
        if err != nil {
            if err == sql.ErrNoRows {
                http.Error(w, `{"error": "Usuario o contraseña inválidos"}`, http.StatusUnauthorized)
            } else {
                log.Printf("Error consultando usuario %s: %v", creds.Username, err)
                http.Error(w, `{"error": "Error interno del servidor"}`, http.StatusInternalServerError)
            }
            return
        }

        if bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(creds.Password)) != nil {
            http.Error(w, `{"error": "Usuario o contraseña inválidos"}`, http.StatusUnauthorized)
            return
        }

        // Genera y almacena el JWT
        tokenString, expirationTime, err := GenerateJWT(userID)
        if err != nil {
            log.Printf("Error generando JWT para user %d: %v", userID, err)
            http.Error(w, `{"error": "Error interno al generar token"}`, http.StatusInternalServerError)
            return
        }

        if err := StoreToken(db, userID, tokenString, expirationTime); err != nil {
            log.Printf("Error guardando token para user %d: %v", userID, err)
            http.Error(w, `{"error": "Error interno al guardar token"}`, http.StatusInternalServerError)
            return
        }

        log.Printf("Login JWT exitoso para usuario ID: %d (%s)", userID, creds.Username)

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
    }
}
