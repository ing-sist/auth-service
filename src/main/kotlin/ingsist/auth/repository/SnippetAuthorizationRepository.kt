package ingsist.auth.repository

import ingsist.auth.entity.AuthorizationTypes
import ingsist.auth.entity.SnippetsAuthorization
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import java.util.Optional

@Repository
interface SnippetAuthorizationRepository : JpaRepository<SnippetsAuthorization, String> {
    /**
     * Busca un permiso específico para un usuario y un snippet.
     */
    fun findByUserIdAndSnippetId(userId: String, snippetId: String): Optional<SnippetsAuthorization>

    /**
     * Verifica si un usuario es el último con permiso de escritura.
     * Importante para evitar que un snippet quede huérfano (sin dueño).
     */
    fun countBySnippetIdAndPermission(snippetId: String, permission: AuthorizationTypes): Long
}