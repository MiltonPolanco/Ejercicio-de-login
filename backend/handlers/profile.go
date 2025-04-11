package handlers

import (
    "database/sql"
    "encoding/json"
    "log"
    "net/http"

    "myapp/backend/models"
)

// GetUserProfileHandler devuelve el perfil del usuario autenticado
func GetUserProfileHandler(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // 1. Obtener el userID que JwtAuthMiddleware guardó en el contexto
        userID, ok := r.Context().Value("userID").(int)
        if !ok || userID == 0 {
            http.Error(w, `{"error":"No se pudo obtener el ID de usuario del token"}`, http.StatusInternalServerError)
            return
        }

        // 2. Consultar en la base de datos los datos del usuario
        var userResp models.UserResponse
        err := db.QueryRow("SELECT id, username FROM users WHERE id = ?", userID).Scan(&userResp.ID, &userResp.Username)
        if err != nil {
            // Si no existe el userID, o hay otro fallo en DB
            http.Error(w, `{"error":"Usuario no encontrado o error en DB"}`, http.StatusNotFound)
            log.Printf("Error consultando perfil: %v", err)
            return
        }

        // 3. Devolver datos del usuario en JSON
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(userResp)
    }
}
