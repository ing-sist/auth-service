package ingsist.auth.entity

enum class AuthorizationTypes(val value: String) {
    WRITE("WRITE"), // Puede editar el snippet
    READ("READ"), // Solo lectura
}
