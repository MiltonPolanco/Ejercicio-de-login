// jwt_utils.go
package handlers

import (
    "context"
    "crypto/sha256"
    "database/sql"
    "encoding/hex"
    "errors"
    "fmt"
    "log"
    "net/http"
    "strings"
    "time"

    "github.com/golang-jwt/jwt/v5"
)

// Clave secreta para firmar el JWT (en producción, usa una variable de entorno segura)
var jwtSecretKey = []byte("mi_clave_secreta_muy_segura_cambiar_esto")

// GenerateJWT crea un nuevo token JWT para un usuario, con validez de 24h.
func GenerateJWT(userID int) (string, time.Time, error) {
    expirationTime := time.Now().Add(24 * time.Hour)
    claims := &jwt.RegisteredClaims{
        Subject:   fmt.Sprintf("%d", userID),
        ExpiresAt: jwt.NewNumericDate(expirationTime),
        IssuedAt:  jwt.NewNumericDate(time.Now()),
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtSecretKey)
    if err != nil {
        return "", time.Time{}, err
    }
    return tokenString, expirationTime, nil
}

// HashToken devuelve el hash SHA256 del token.
func HashToken(token string) string {
    hasher := sha256.New()
    hasher.Write([]byte(token))
    return hex.EncodeToString(hasher.Sum(nil))
}

// StoreToken guarda el hash del token junto con el userID y la fecha de expiración en la DB.
func StoreToken(db *sql.DB, userID int, token string, expiresAt time.Time) error {
    tokenHash := HashToken(token)
    stmt, err := db.Prepare("INSERT INTO active_tokens(user_id, token_hash, expires_at) VALUES(?, ?, ?)")
    if err != nil {
        return fmt.Errorf("error preparando statement para guardar token: %w", err)
    }
    defer stmt.Close()
    _, err = stmt.Exec(userID, tokenHash, expiresAt)
    if err != nil {
        return fmt.Errorf("error ejecutando statement para guardar token: %w", err)
    }
    return nil
}

// InvalidateToken elimina el token de la DB (lo invalida).
func InvalidateToken(db *sql.DB, token string) error {
    tokenHash := HashToken(token)
    stmt, err := db.Prepare("DELETE FROM active_tokens WHERE token_hash = ?")
    if err != nil {
        return fmt.Errorf("error preparando statement para invalidar token: %w", err)
    }
    defer stmt.Close()
    result, err := stmt.Exec(tokenHash)
    if err != nil {
        return fmt.Errorf("error ejecutando statement para invalidar token: %w", err)
    }
    rowsAffected, _ := result.RowsAffected()
    if rowsAffected == 0 {
        log.Printf("Intento de invalidar token no encontrado o ya invalidado (hash: %s...)", tokenHash[:10])
    } else {
        log.Printf("Token invalidado exitosamente (hash: %s...)", tokenHash[:10])
    }
    return nil
}

// ValidateTokenAndGetUserID verifica el token y lo confirma en la DB.
func ValidateTokenAndGetUserID(db *sql.DB, tokenString string) (int, error) {
    claims := &jwt.RegisteredClaims{}
    token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
        if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("método de firma inesperado: %v", t.Header["alg"])
        }
        return jwtSecretKey, nil
    })
    if err != nil {
        return 0, fmt.Errorf("error parseando token: %w", err)
    }
    if !token.Valid {
        return 0, errors.New("token inválido")
    }
    // Verificar en la DB si el token (su hash) está activo
    tokenHash := HashToken(tokenString)
    var dbUserID int
    var expiresAt time.Time
    err = db.QueryRow("SELECT user_id, expires_at FROM active_tokens WHERE token_hash = ?", tokenHash).Scan(&dbUserID, &expiresAt)
    if err != nil {
        if err == sql.ErrNoRows {
            return 0, errors.New("token no encontrado o inactivo en DB")
        }
        return 0, fmt.Errorf("error consultando token en DB: %w", err)
    }
    if time.Now().After(expiresAt) {
        go func() {
            _ = InvalidateToken(db, tokenString)
        }()
        return 0, errors.New("token expirado según la DB")
    }
    var claimUserID int
    _, convErr := fmt.Sscan(claims.Subject, &claimUserID)
    if convErr != nil {
        return 0, fmt.Errorf("no se pudo convertir subject a int: %w", convErr)
    }
    if claimUserID != dbUserID {
        return 0, errors.New("discrepancia de userID entre token y DB")
    }
    return dbUserID, nil
}

// JwtAuthMiddleware es el middleware que valida el token en cada request.
func JwtAuthMiddleware(db *sql.DB) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" {
                http.Error(w, "Falta header de autorización", http.StatusUnauthorized)
                return
            }
            parts := strings.Split(authHeader, " ")
            if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
                http.Error(w, "Header de autorización mal formado, se espera 'Bearer <token>'", http.StatusUnauthorized)
                return
            }
            tokenString := parts[1]
            userID, err := ValidateTokenAndGetUserID(db, tokenString)
            if err != nil {
                log.Printf("Error validando token: %v", err)
                http.Error(w, "Token inválido o expirado", http.StatusUnauthorized)
                return
            }
            ctx := context.WithValue(r.Context(), "userID", userID)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
