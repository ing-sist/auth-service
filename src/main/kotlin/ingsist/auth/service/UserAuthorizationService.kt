package ingsist.auth.service

import ingsist.auth.entity.SnippetsAuthorization
import ingsist.auth.repository.SnippetAuthorizationRepository
import org.springframework.stereotype.Service

@Service
class UserAuthorizationService(private val repository: SnippetAuthorizationRepository) {
    /**
     * Obtiene todos los permisos para un usuario.
     */
    fun getPermissionsForUser(userId: String): List<SnippetsAuthorization> {
        return repository.findAllByUserId(userId)
    }
}
