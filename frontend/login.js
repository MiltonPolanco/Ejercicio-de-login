// login.js (Actualizado para JWT)
document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm')
    const messageElement = document.getElementById('loginMessage')
    const backendUrl = 'http://localhost:3000' // URL base del API

    loginForm.addEventListener('submit', async (event) => {
        event.preventDefault()
        const username = document.getElementById('username').value
        const password = document.getElementById('password').value
        messageElement.textContent = ''

        if (!username || !password) {
            messageElement.textContent = 'Por favor llenen todos los campos.'
            return
        }

        try {
            const response = await fetch(`${backendUrl}/auth/login`, { // Ruta actualizada para JWT
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            })

            const data = await response.json()

            if (response.ok) { // Login exitoso, se espera que se reciba un token
                if (data.token) {
                    // --- INICIO CAMBIOS JWT ---
                    // Guardar el token JWT en localStorage
                    localStorage.setItem('jwtToken', data.token)
                    // Remover otras claves si existen
                    localStorage.removeItem('userId')
                    localStorage.removeItem('username')
                    // --- FIN CAMBIOS JWT ---

                    // Redirigir a la página de perfil
                    window.location.href = 'profile.html'
                } else {
                    messageElement.textContent = 'Error: No se recibió token del servidor.'
                }
            } else { // Error
                messageElement.textContent = `Error: ${data.error || 'Usuario o contraseña inválidos'}`
                localStorage.removeItem('jwtToken') // Limpiar token en caso de error
            }
        } catch (error) {
            console.error('Error de login:', error)
            messageElement.textContent = 'Login falló. Problema de red o del servidor.'
            localStorage.removeItem('jwtToken')
        }
    })
})
