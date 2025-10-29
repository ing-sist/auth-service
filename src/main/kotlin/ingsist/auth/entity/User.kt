package ingsist.auth.entity

import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table

/**
 * Representa a un usuario en el sistema.
 * La información se sincroniza desde el token de Auth0.
 */
@Entity
@Table(name = "users")
data class User(
    @Id
    val id: String, // Corresponde al 'subject' del token JWT
    val name: String,
)