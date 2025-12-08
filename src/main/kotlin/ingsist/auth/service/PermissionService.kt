package ingsist.auth.service

import ingsist.auth.dto.SharedSnippetDto
import ingsist.auth.entity.AuthorizationTypes
import ingsist.auth.entity.SnippetsAuthorization
import ingsist.auth.exceptions.PermissionAlreadyExistsException
import ingsist.auth.exceptions.UnauthorizedException
import ingsist.auth.repository.SnippetAuthorizationRepository
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class PermissionService(
    private val repository: SnippetAuthorizationRepository,
    private val auth0ManagementService: Auth0ManagementService,
) {
    val log = LoggerFactory.getLogger(PermissionService::class.java)

    @Transactional
    fun createAuthorization(
        request: ingsist.auth.dto.GrantPermissionDto,
        requestingUserId: String,
    ): SnippetsAuthorization {
        log.info("Creating authorization for user ${request.userId} on snippet ${request.snippetId}")
        val snippetId = request.snippetId ?: throw IllegalArgumentException("Snippet ID is required")
        log.info(
            "Granting ${request.permission} permission on snippet $snippetId" +
                " to user ${request.userId} by requester $requestingUserId",
        )
        return grantPermission(request.userId, snippetId, request.permission, requestingUserId)
    }

    @Transactional
    fun grantPermission(
        targetUserId: String,
        snippetId: String,
        permissionToGrant: AuthorizationTypes,
        requestingUserId: String,
    ): SnippetsAuthorization {
        log.info(
            "Granting $permissionToGrant permission on snippet $snippetId" +
                " to user $targetUserId by requester $requestingUserId",
        )
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
        log.info("Saving new permission: $newPermission for user $targetUserId on snippet $snippetId")
        return repository.save(newPermission)
    }

    fun hasPermission(
        userId: String,
        snippetId: String,
        requiredPermission: AuthorizationTypes,
    ): Boolean {
        log.info("Checking if user $userId has $requiredPermission permission on snippet $snippetId")
        val userPermission = repository.findByUserIdAndSnippetId(userId, snippetId).orElse(null)

        return when (requiredPermission) {
            AuthorizationTypes.WRITE -> {
                userPermission?.permission == AuthorizationTypes.WRITE
            }
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
        log.info("Validating that user $userId has $requiredPermission permission on snippet $snippetId")
        if (!hasPermission(userId, snippetId, requiredPermission)) {
            log.info("User $userId lacks $requiredPermission permission on snippet $snippetId")
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
        log.info("Validating that user $userId can grant permissions on snippet $snippetId")
        val userPermission = repository.findByUserIdAndSnippetId(userId, snippetId).orElse(null)

        if (userPermission == null) {
            if (repository.countBySnippetId(snippetId) == 0L) {
                return
            }
            log.info("User $userId has no permissions on snippet $snippetId to grant access.")
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
        log.info("Validating that user $userId can revoke permissions on snippet $snippetId")
        checkPermission(userId, snippetId, AuthorizationTypes.WRITE)
        log.info("User $userId is authorized to revoke permissions on snippet $snippetId")
    }

    /**
     * Obtiene todos los permisos para un snippet.
     * Incluye una validación de seguridad.
     */
    fun getPermissionsForSnippet(
        snippetId: String,
        requestingUserId: String,
    ): List<SharedSnippetDto> {
        log.info("Fetching permissions for snippet $snippetId requested by user $requestingUserId")
        // Seguridad: Solo un "owner" (WRITE) puede ver la lista de permisos
        validateUserCanRevokePermission(requestingUserId, snippetId)
        log.info("User $requestingUserId is authorized to view permissions for snippet $snippetId")
        val permissions = repository.findAllBySnippetId(snippetId)

        log.info("Found ${permissions.size} permissions for snippet $snippetId")
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
        log.info("Fetching permissions for user $userId")
        val permissions = repository.findAllByUserId(userId)

        log.info("Found ${permissions.size} permissions for user $userId")
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
