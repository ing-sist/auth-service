// src/main/kotlin/ingsist/auth/service/AuthorizationService.kt
package ingsist.auth.service

import ingsist.auth.dto.SnippetAuthorizationDto
import ingsist.auth.entity.AuthorizationTypes
import ingsist.auth.entity.SnippetsAuthorization
import ingsist.auth.exceptions.CannotRevokeLastWritePermissionException
import ingsist.auth.exceptions.PermissionAlreadyExistsException
import ingsist.auth.exceptions.PermissionNotFoundException
import ingsist.auth.exceptions.UnauthorizedException
import ingsist.auth.repository.SnippetAuthorizationRepository
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class AuthorizationService(
    private val repository: SnippetAuthorizationRepository,
    private val auth0ManagementService: Auth0ManagementService,
) {
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

    @Transactional
    fun revokePermission(
        targetUserId: String,
        snippetId: String,
        requestingUserId: String,
    ) {
        // 1. Validate that the requesting user can revoke permissions.
        validateUserCanRevokePermission(requestingUserId, snippetId)

        // 2. Find the permission to revoke.
        val permissionToRevoke =
            repository.findByUserIdAndSnippetId(targetUserId, snippetId)
                .orElseThrow {
                    PermissionNotFoundException(
                        "No permission found for " +
                            "user $targetUserId on snippet $snippetId",
                    )
                }

        // 3. Check if revoking this permission would leave the snippet without any WRITE permissions.
        if (permissionToRevoke.permission == AuthorizationTypes.WRITE) {
            if (isLastWriter(snippetId)) {
                throw CannotRevokeLastWritePermissionException(
                    "Cannot revoke the " +
                        "last WRITE permission for snippet $snippetId",
                )
            }
        }
        // 4. Revoke the permission.
        repository.delete(permissionToRevoke)
    }

    fun checkPermission(
        userId: String,
        snippetId: String,
        requiredPermission: AuthorizationTypes,
    ) {
        val userPermission = repository.findByUserIdAndSnippetId(userId, snippetId).orElse(null)

        val hasPermission =
            when (requiredPermission) {
                AuthorizationTypes.WRITE -> userPermission?.permission == AuthorizationTypes.WRITE
                AuthorizationTypes.READ ->
                    userPermission?.permission in
                        listOf(
                            AuthorizationTypes.READ,
                            AuthorizationTypes.WRITE,
                        )
            }

        if (!hasPermission) {
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

    private fun isLastWriter(snippetId: String): Boolean {
        return repository.countBySnippetIdAndPermission(snippetId, AuthorizationTypes.WRITE) <= 1
    }

    /**
     * NUEVO: Obtiene un permiso o falla (404).
     * Reemplaza la necesidad de 'check'.
     */
    fun getPermission(
        userId: String,
        snippetId: String,
    ): SnippetsAuthorization {
        return repository.findByUserIdAndSnippetId(userId, snippetId)
            .orElseThrow {
                PermissionNotFoundException(
                    "No permission found for user $userId on snippet $snippetId",
                )
            }
    }

    /**
     * Obtiene todos los permisos para un snippet.
     * Incluye una validación de seguridad.
     */
    fun getPermissionsForSnippet(
        snippetId: String,
        requestingUserId: String,
    ): List<SnippetAuthorizationDto> {
        // Seguridad: Solo un "owner" (WRITE) puede ver la lista de permisos
        validateUserCanRevokePermission(requestingUserId, snippetId)
        val permissions = repository.findAllBySnippetId(snippetId)

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
