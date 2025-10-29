package ingsist.auth.service

import ingsist.auth.entity.AuthorizationTypes
import ingsist.auth.entity.SnippetsAuthorization
import ingsist.auth.repository.SnippetAuthorizationRepository
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import ingsist.auth.exceptions.UnauthorizedException
import ingsist.auth.exceptions.PermissionAlreadyExistsException
import ingsist.auth.exceptions.PermissionNotFoundException
import ingsist.auth.exceptions.CannotRevokeLastWritePermissionException

@Service
class AuthorizationService(private val repository: SnippetAuthorizationRepository) {
    fun checkPermission(userId: String, snippetId: String, requiredPermission: AuthorizationTypes) {
        val userPermission = repository.findByUserIdAndSnippetId(userId, snippetId)
            .orElse(null)

        val hasPermission = when (requiredPermission) {
            AuthorizationTypes.WRITE -> userPermission?.permission == AuthorizationTypes.WRITE
            AuthorizationTypes.READ -> userPermission?.permission in listOf(AuthorizationTypes.READ, AuthorizationTypes.WRITE)
        }

        if (!hasPermission) {
            throw UnauthorizedException("User $userId does not have $requiredPermission permission on snippet $snippetId")
        }
    }


    @Transactional
    fun grantPermission(targetUserId: String, snippetId: String, permissionToGrant: AuthorizationTypes, requestingUserId: String) {
        // Un usuario solo puede otorgar permisos si él mismo tiene permiso de WRITE.
        checkPermission(requestingUserId, snippetId, AuthorizationTypes.WRITE)

        val existingPermission = repository.findByUserIdAndSnippetId(targetUserId, snippetId)
        if (existingPermission.isPresent) {
            throw PermissionAlreadyExistsException("User $targetUserId already has a permission on snippet $snippetId")
        }

        val newPermission = SnippetsAuthorization(
            userId = targetUserId,
            snippetId = snippetId,
            permission = permissionToGrant
        )
        repository.save(newPermission)
    }


    @Transactional
    fun revokePermission(targetUserId: String, snippetId: String, requestingUserId: String) {
        // El que revoca debe tener permiso de WRITE.
        checkPermission(requestingUserId, snippetId, AuthorizationTypes.WRITE)

        val permissionToRevoke = repository.findByUserIdAndSnippetId(targetUserId, snippetId)
            .orElseThrow { PermissionNotFoundException("No permission found for user $targetUserId on snippet $snippetId") }

        // Lógica para evitar que un snippet se quede sin "dueño".
        if (permissionToRevoke.permission == AuthorizationTypes.WRITE) {
            val writersCount = repository.countBySnippetIdAndPermission(snippetId, AuthorizationTypes.WRITE)
            if (writersCount <= 1) {
                throw CannotRevokeLastWritePermissionException("Cannot revoke the last WRITE permission for snippet $snippetId")
            }
        }

        repository.delete(permissionToRevoke)
    }
}