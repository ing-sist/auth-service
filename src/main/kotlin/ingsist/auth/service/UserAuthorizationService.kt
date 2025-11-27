package ingsist.auth.service

import ingsist.auth.dto.SnippetAuthorizationDto
import ingsist.auth.repository.SnippetAuthorizationRepository
import org.springframework.stereotype.Service

@Service
class UserAuthorizationService(
    private val repository: SnippetAuthorizationRepository,
    private val auth0ManagementService: Auth0ManagementService,
) {
    /**
     * Obtiene todos los permisos para un usuario.
     */
    fun getPermissionsForUser(userId: String): List<SnippetAuthorizationDto> {
        val permissions = repository.findAllByUserId(userId)

        // Mapeamos cada permiso buscando el email
        return permissions.map { permission ->
            val email = auth0ManagementService.getUserEmail(permission.userId)

            SnippetAuthorizationDto(
                id = permission.id,
                snippetId = permission.snippetId,
                userId = permission.userId,
                userEmail = email,
                permission = permission.permission,
            )
        }
    }
}
