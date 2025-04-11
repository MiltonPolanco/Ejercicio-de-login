package main

import (
    "log"
    "net/http"

    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
    "myapp/backend/handlers"
)

func main() {
    db, err := setupDatabase("./users.db")
    if err != nil {
        log.Fatal("No se pudo conectar a la base de datos:", err)
    }
    defer db.Close()

    r := chi.NewRouter()
    r.Use(middleware.Logger)
    r.Use(middleware.Recoverer)
    r.Use(configureCORS())

    // Rutas públicas
    r.Route("/auth", func(r chi.Router) {
        r.Post("/register", handlers.PostRegisterHandler(db))
        r.Post("/login", handlers.PostLoginHandler(db))
    })
    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("API con JWT"))
    })

    // Rutas protegidas
    r.Group(func(r chi.Router) {
        r.Use(handlers.JwtAuthMiddleware(db))
        r.Post("/auth/logout", handlers.PostLogoutHandler(db))
        r.Get("/users/profile", handlers.GetUserProfileHandler(db))
    })

    // Una ruta pública o protegida adicional
    r.Get("/users/{userID}", handlers.GetUserHandler(db))

    port := ":3000"
    log.Printf("Servidor escuchando en puerto %s", port)
    log.Fatal(http.ListenAndServe(port, r))
}
