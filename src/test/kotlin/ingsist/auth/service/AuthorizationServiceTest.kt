package ingsist.auth.service

import ingsist.auth.entity.AuthorizationTypes
import ingsist.auth.entity.SnippetsAuthorization
import ingsist.auth.exceptions.CannotRevokeLastWritePermissionException
import ingsist.auth.exceptions.PermissionAlreadyExistsException
import ingsist.auth.exceptions.PermissionNotFoundException
import ingsist.auth.exceptions.UnauthorizedException
import ingsist.auth.repository.SnippetAuthorizationRepository
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.Mockito.never
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.any
import java.util.Optional

@ExtendWith(MockitoExtension::class)
class AuthorizationServiceTest {
    @Mock
    private lateinit var repository: SnippetAuthorizationRepository

    @InjectMocks
    private lateinit var service: AuthorizationService

    @Test
    fun `grantPermission should create and return new permission for first user on new snippet`() {
        val targetUserId = "user456"
        val snippetId = "snippet-1"
        val requestingUserId = "user123"
        val permission = AuthorizationTypes.WRITE

        `when`(repository.findByUserIdAndSnippetId(requestingUserId, snippetId))
            .thenReturn(Optional.empty())
        `when`(repository.countBySnippetId(snippetId)).thenReturn(0L)
        `when`(repository.findByUserIdAndSnippetId(targetUserId, snippetId))
            .thenReturn(Optional.empty())
        `when`(repository.save(any())).thenAnswer { it.arguments[0] }

        val result =
            service.grantPermission(
                targetUserId = targetUserId,
                snippetId = snippetId,
                permissionToGrant = permission,
                requestingUserId = requestingUserId,
            )

        assertNotNull(result)
        assertEquals(targetUserId, result.userId)
        assertEquals(snippetId, result.snippetId)
        assertEquals(permission, result.permission)
        verify(repository).save(any())
    }

    @Test
    fun `grantPermission should create and return new permission when user has WRITE permission`() {
        val targetUserId = "user456"
        val snippetId = "snippet-1"
        val requestingUserId = "user123"
        val permission = AuthorizationTypes.READ
        val requestingUserPermission =
            SnippetsAuthorization(
                id = "perm-1",
                snippetId = snippetId,
                userId = requestingUserId,
                permission = AuthorizationTypes.WRITE,
            )

        `when`(repository.findByUserIdAndSnippetId(requestingUserId, snippetId))
            .thenReturn(Optional.of(requestingUserPermission))
        `when`(repository.findByUserIdAndSnippetId(targetUserId, snippetId))
            .thenReturn(Optional.empty())
        `when`(repository.save(any())).thenAnswer { it.arguments[0] }

        val result =
            service.grantPermission(
                targetUserId = targetUserId,
                snippetId = snippetId,
                permissionToGrant = permission,
                requestingUserId = requestingUserId,
            )

        assertNotNull(result)
        assertEquals(targetUserId, result.userId)
        assertEquals(snippetId, result.snippetId)
        assertEquals(permission, result.permission)
    }

    @Test
    fun `grantPermission should throw UnauthorizedException when user has no permissions on existing snippet`() {
        val targetUserId = "user456"
        val snippetId = "snippet-1"
        val requestingUserId = "user123"

        `when`(repository.findByUserIdAndSnippetId(requestingUserId, snippetId))
            .thenReturn(Optional.empty())
        `when`(repository.countBySnippetId(snippetId)).thenReturn(1L)

        val exception =
            org.junit.jupiter.api.assertThrows<UnauthorizedException> {
                service.grantPermission(
                    targetUserId = targetUserId,
                    snippetId = snippetId,
                    permissionToGrant = AuthorizationTypes.READ,
                    requestingUserId = requestingUserId,
                )
            }
        val message = "User $requestingUserId has no permissions on snippet $snippetId to grant access."
        assertEquals(message, exception.message)
        verify(repository, never()).save(any())
    }

    @Test
    fun `grantPermission should throw UnauthorizedException when user has READ permission`() {
        val targetUserId = "user456"
        val snippetId = "snippet-1"
        val requestingUserId = "user123"
        val requestingUserPermission =
            SnippetsAuthorization(
                id = "perm-1",
                snippetId = snippetId,
                userId = requestingUserId,
                permission = AuthorizationTypes.READ,
            )

        `when`(repository.findByUserIdAndSnippetId(requestingUserId, snippetId))
            .thenReturn(Optional.of(requestingUserPermission))

        val exception =
            org.junit.jupiter.api.assertThrows<UnauthorizedException> {
                service.grantPermission(
                    targetUserId = targetUserId,
                    snippetId = snippetId,
                    permissionToGrant = AuthorizationTypes.READ,
                    requestingUserId = requestingUserId,
                )
            }

        assertEquals("User $requestingUserId does not have WRITE permission to grant access.", exception.message)
    }

    @Test
    fun `grantPermission should throw PermissionAlreadyExistsException when target user already has permission`() {
        val targetUserId = "user456"
        val snippetId = "snippet-1"
        val requestingUserId = "user123"
        val requestingUserPermission =
            SnippetsAuthorization(
                id = "perm-1",
                snippetId = snippetId,
                userId = requestingUserId,
                permission = AuthorizationTypes.WRITE,
            )
        val existingPermission =
            SnippetsAuthorization(
                id = "perm-2",
                snippetId = snippetId,
                userId = targetUserId,
                permission = AuthorizationTypes.READ,
            )

        `when`(repository.findByUserIdAndSnippetId(requestingUserId, snippetId))
            .thenReturn(Optional.of(requestingUserPermission))
        `when`(repository.findByUserIdAndSnippetId(targetUserId, snippetId))
            .thenReturn(Optional.of(existingPermission))

        val exception =
            org.junit.jupiter.api.assertThrows<PermissionAlreadyExistsException> {
                service.grantPermission(
                    targetUserId = targetUserId,
                    snippetId = snippetId,
                    permissionToGrant = AuthorizationTypes.WRITE,
                    requestingUserId = requestingUserId,
                )
            }

        assertEquals("User $targetUserId already has a permission on snippet $snippetId", exception.message)
    }

    @Test
    fun `revokePermission should delete permission when valid`() {
        val targetUserId = "user456"
        val snippetId = "snippet-1"
        val requestingUserId = "user123"
        val requestingUserPermission =
            SnippetsAuthorization(
                id = "perm-1",
                snippetId = snippetId,
                userId = requestingUserId,
                permission = AuthorizationTypes.WRITE,
            )
        val targetUserPermission =
            SnippetsAuthorization(
                id = "perm-2",
                snippetId = snippetId,
                userId = targetUserId,
                permission = AuthorizationTypes.READ,
            )

        `when`(repository.findByUserIdAndSnippetId(requestingUserId, snippetId))
            .thenReturn(Optional.of(requestingUserPermission))
        `when`(repository.findByUserIdAndSnippetId(targetUserId, snippetId))
            .thenReturn(Optional.of(targetUserPermission))

        service.revokePermission(
            targetUserId = targetUserId,
            snippetId = snippetId,
            requestingUserId = requestingUserId,
        )

        verify(repository).delete(targetUserPermission)
    }

    @Test
    fun `revokePermission should throw PermissionNotFoundException when target permission not found`() {
        val targetUserId = "user456"
        val snippetId = "snippet-1"
        val requestingUserId = "user123"
        val requestingUserPermission =
            SnippetsAuthorization(
                id = "perm-1",
                snippetId = snippetId,
                userId = requestingUserId,
                permission = AuthorizationTypes.WRITE,
            )

        `when`(repository.findByUserIdAndSnippetId(requestingUserId, snippetId))
            .thenReturn(Optional.of(requestingUserPermission))
        `when`(repository.findByUserIdAndSnippetId(targetUserId, snippetId))
            .thenReturn(Optional.empty())

        val exception =
            org.junit.jupiter.api.assertThrows<PermissionNotFoundException> {
                service.revokePermission(
                    targetUserId = targetUserId,
                    snippetId = snippetId,
                    requestingUserId = requestingUserId,
                )
            }

        assertEquals("No permission found for user $targetUserId on snippet $snippetId", exception.message)
    }

    @Test
    fun `revokePermission should throw CannotRevokeLastWritePermissionException when revoking last WRITE permission`() {
        val targetUserId = "user456"
        val snippetId = "snippet-1"
        val requestingUserId = "user123"
        val requestingUserPermission =
            SnippetsAuthorization(
                id = "perm-1",
                snippetId = snippetId,
                userId = requestingUserId,
                permission = AuthorizationTypes.WRITE,
            )
        val targetUserPermission =
            SnippetsAuthorization(
                id = "perm-2",
                snippetId = snippetId,
                userId = targetUserId,
                permission = AuthorizationTypes.WRITE,
            )

        `when`(repository.findByUserIdAndSnippetId(requestingUserId, snippetId))
            .thenReturn(Optional.of(requestingUserPermission))
        `when`(repository.findByUserIdAndSnippetId(targetUserId, snippetId))
            .thenReturn(Optional.of(targetUserPermission))
        `when`(repository.countBySnippetIdAndPermission(snippetId, AuthorizationTypes.WRITE))
            .thenReturn(1L)

        val exception =
            org.junit.jupiter.api.assertThrows<CannotRevokeLastWritePermissionException> {
                service.revokePermission(
                    targetUserId = targetUserId,
                    snippetId = snippetId,
                    requestingUserId = requestingUserId,
                )
            }

        assertEquals("Cannot revoke the last WRITE permission for snippet $snippetId", exception.message)
    }

    @Test
    fun `checkPermission should not throw when user has WRITE permission and READ is required`() {
        val userId = "user123"
        val snippetId = "snippet-1"
        val userPermission =
            SnippetsAuthorization(
                id = "perm-1",
                snippetId = snippetId,
                userId = userId,
                permission = AuthorizationTypes.WRITE,
            )

        `when`(repository.findByUserIdAndSnippetId(userId, snippetId))
            .thenReturn(Optional.of(userPermission))

        service.checkPermission(userId, snippetId, AuthorizationTypes.READ)
        // No exception should be thrown
    }

    @Test
    fun `checkPermission should not throw when user has exact permission`() {
        val userId = "user123"
        val snippetId = "snippet-1"
        val userPermission =
            SnippetsAuthorization(
                id = "perm-1",
                snippetId = snippetId,
                userId = userId,
                permission = AuthorizationTypes.READ,
            )

        `when`(repository.findByUserIdAndSnippetId(userId, snippetId))
            .thenReturn(Optional.of(userPermission))

        service.checkPermission(userId, snippetId, AuthorizationTypes.READ)
        // No exception should be thrown
    }

    @Test
    fun `checkPermission should throw UnauthorizedException when user has READ but WRITE is required`() {
        val userId = "user123"
        val snippetId = "snippet-1"
        val userPermission =
            SnippetsAuthorization(
                id = "perm-1",
                snippetId = snippetId,
                userId = userId,
                permission = AuthorizationTypes.READ,
            )

        `when`(repository.findByUserIdAndSnippetId(userId, snippetId))
            .thenReturn(Optional.of(userPermission))

        val exception =
            org.junit.jupiter.api.assertThrows<UnauthorizedException> {
                service.checkPermission(userId, snippetId, AuthorizationTypes.WRITE)
            }

        assertEquals("User $userId does not have WRITE permission on snippet $snippetId", exception.message)
    }

    @Test
    fun `checkPermission should throw UnauthorizedException when user has no permission`() {
        val userId = "user123"
        val snippetId = "snippet-1"

        `when`(repository.findByUserIdAndSnippetId(userId, snippetId))
            .thenReturn(Optional.empty())

        val exception =
            org.junit.jupiter.api.assertThrows<UnauthorizedException> {
                service.checkPermission(userId, snippetId, AuthorizationTypes.READ)
            }

        assertEquals("User $userId does not have READ permission on snippet $snippetId", exception.message)
    }

    @Test
    fun `getPermission should return permission when found`() {
        val userId = "user123"
        val snippetId = "snippet-1"
        val expectedPermission =
            SnippetsAuthorization(
                id = "perm-1",
                snippetId = snippetId,
                userId = userId,
                permission = AuthorizationTypes.READ,
            )

        `when`(repository.findByUserIdAndSnippetId(userId, snippetId))
            .thenReturn(Optional.of(expectedPermission))

        val result = service.getPermission(userId, snippetId)

        assertEquals(expectedPermission, result)
    }

    @Test
    fun `getPermission should throw PermissionNotFoundException when not found`() {
        val userId = "user123"
        val snippetId = "snippet-1"

        `when`(repository.findByUserIdAndSnippetId(userId, snippetId))
            .thenReturn(Optional.empty())

        val exception =
            org.junit.jupiter.api.assertThrows<PermissionNotFoundException> {
                service.getPermission(userId, snippetId)
            }

        assertEquals("No permission found for user $userId on snippet $snippetId", exception.message)
    }

    @Test
    fun `getPermissionsForSnippet should return list of permissions when user has WRITE permission`() {
        val snippetId = "snippet-1"
        val requestingUserId = "user123"
        val requestingUserPermission =
            SnippetsAuthorization(
                id = "perm-1",
                snippetId = snippetId,
                userId = requestingUserId,
                permission = AuthorizationTypes.WRITE,
            )
        val expectedPermissions =
            listOf(
                requestingUserPermission,
                SnippetsAuthorization(
                    id = "perm-2",
                    snippetId = snippetId,
                    userId = "user456",
                    permission = AuthorizationTypes.READ,
                ),
            )

        `when`(repository.findByUserIdAndSnippetId(requestingUserId, snippetId))
            .thenReturn(Optional.of(requestingUserPermission))
        `when`(repository.findAllBySnippetId(snippetId))
            .thenReturn(expectedPermissions)

        val result = service.getPermissionsForSnippet(snippetId, requestingUserId)

        assertEquals(expectedPermissions, result)
    }

    @Test
    fun `getPermissionsForSnippet should throw UnauthorizedException when user lacks WRITE permission`() {
        val snippetId = "snippet-1"
        val requestingUserId = "user123"
        val requestingUserPermission =
            SnippetsAuthorization(
                id = "perm-1",
                snippetId = snippetId,
                userId = requestingUserId,
                permission = AuthorizationTypes.READ,
            )

        `when`(repository.findByUserIdAndSnippetId(requestingUserId, snippetId))
            .thenReturn(Optional.of(requestingUserPermission))

        val exception =
            org.junit.jupiter.api.assertThrows<UnauthorizedException> {
                service.getPermissionsForSnippet(snippetId, requestingUserId)
            }

        assertEquals("User $requestingUserId does not have WRITE permission on snippet $snippetId", exception.message)
    }
}
