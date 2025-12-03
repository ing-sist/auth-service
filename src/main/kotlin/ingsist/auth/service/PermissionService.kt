// src/main/kotlin/ingsist/auth/service/AuthorizationService.kt
package ingsist.auth.service

import ingsist.auth.dto.SharedSnippetDto
import ingsist.auth.entity.AuthorizationTypes
import ingsist.auth.entity.SnippetsAuthorization
import ingsist.auth.exceptions.PermissionAlreadyExistsException
import ingsist.auth.exceptions.UnauthorizedException
import ingsist.auth.repository.SnippetAuthorizationRepository
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class PermissionService(
    private val repository: SnippetAuthorizationRepository,
    private val auth0ManagementService: Auth0ManagementService,
) {
    @Transactional
    fun createAuthorization(
        request: ingsist.auth.dto.GrantPermissionDto,
        requestingUserId: String,
    ): SnippetsAuthorization {
        val snippetId = request.snippetId ?: throw IllegalArgumentException("Snippet ID is required")
        return grantPermission(request.userId, snippetId, request.permission, requestingUserId)
    }

    @Transactional
    fun grantPermission(
        targetUserId: String,
        snippetId: String,
        permissionToGrant: AuthorizationTypes,
        requestingUserId: String,
    ): SnippetsAuthorization {
        // 1. User can grant permissions
        validateUserCanGrantPermission(requestingUserId, snippetId)

        // 2. User already has permission?
        val existingPermission = repository.findByUserIdAndSnippetId(targetUserId, snippetId)
        if (existingPermission.isPresent) {
            throw PermissionAlreadyExistsException(
                "User $targetUserId already has a permission on snippet $snippetId",
            )
        }

        // 3. Create and save new permission
        val newPermission =
            SnippetsAuthorization(
                userId = targetUserId,
                snippetId = snippetId,
                permission = permissionToGrant,
            )
        return repository.save(newPermission)
    }

    fun hasPermission(
        userId: String,
        snippetId: String,
        requiredPermission: AuthorizationTypes,
    ): Boolean {
        val userPermission = repository.findByUserIdAndSnippetId(userId, snippetId).orElse(null)

        return when (requiredPermission) {
            AuthorizationTypes.WRITE -> userPermission?.permission == AuthorizationTypes.WRITE
            AuthorizationTypes.READ ->
                userPermission?.permission in
                    listOf(
                        AuthorizationTypes.READ,
                        AuthorizationTypes.WRITE,
                    )
        }
    }

    private fun checkPermission(
        userId: String,
        snippetId: String,
        requiredPermission: AuthorizationTypes,
    ) {
        if (!hasPermission(userId, snippetId, requiredPermission)) {
            throw UnauthorizedException(
                "User $userId does not have " +
                    "$requiredPermission permission on snippet $snippetId",
            )
        }
    }

    private fun validateUserCanGrantPermission(
        userId: String,
        snippetId: String,
    ) {
        val userPermission = repository.findByUserIdAndSnippetId(userId, snippetId).orElse(null)

        if (userPermission == null) {
            if (repository.countBySnippetId(snippetId) == 0L) {
                return
            }
            throw UnauthorizedException(
                "User $userId has no permissions " +
                    "on snippet $snippetId to grant access.",
            )
        }

        if (userPermission.permission != AuthorizationTypes.WRITE) {
            throw UnauthorizedException("User $userId does not have WRITE permission to grant access.")
        }
    }

    private fun validateUserCanRevokePermission(
        userId: String,
        snippetId: String,
    ) {
        checkPermission(userId, snippetId, AuthorizationTypes.WRITE)
    }

    /**
     * Obtiene todos los permisos para un snippet.
     * Incluye una validación de seguridad.
     */
    fun getPermissionsForSnippet(
        snippetId: String,
        requestingUserId: String,
    ): List<SharedSnippetDto> {
        // Seguridad: Solo un "owner" (WRITE) puede ver la lista de permisos
        validateUserCanRevokePermission(requestingUserId, snippetId)
        val permissions = repository.findAllBySnippetId(snippetId)

        // Mapeamos cada permiso buscando el email
        return permissions.map { permission ->
            val email = auth0ManagementService.getUserEmail(permission.userId)

            SharedSnippetDto(
                id = permission.id,
                snippetId = permission.snippetId,
                userId = permission.userId,
                userEmail = email,
                permission = permission.permission,
            )
        }
    }

    // Removed redundant wrapper methods to reduce function count

    /**
     * Obtiene todos los permisos para un usuario.
     */
    fun getPermissionsForUser(userId: String): List<SharedSnippetDto> {
        val permissions = repository.findAllByUserId(userId)

        // Mapeamos cada permiso buscando el email
        return permissions.map { permission ->
            val email = auth0ManagementService.getUserEmail(permission.userId)

            SharedSnippetDto(
                id = permission.id,
                snippetId = permission.snippetId,
                userId = permission.userId,
                userEmail = email,
                permission = permission.permission,
            )
        }
    }

    @Transactional
    fun deleteSnippet(
        snippetId: String,
        requestingUserId: String,
    ) {
        // 1. Validate that the requesting user can delete the snippet (must be owner/writer)
        validateUserCanRevokePermission(requestingUserId, snippetId)

        // 2. Delete all permissions for the snippet
        repository.deleteAllBySnippetId(snippetId)
    }
}
