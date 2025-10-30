package ingsist.auth.entity

import jakarta.persistence.Entity
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.util.UUID

/**
 * Define la relación de permiso entre un usuario y un snippet.
 */
@Entity
@Table(name = "snippet_authorizations")
data class SnippetsAuthorization(
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    var id: String? = null,
    val snippetId: String,
    val userId: String,
    val permission: AuthorizationTypes,
)
