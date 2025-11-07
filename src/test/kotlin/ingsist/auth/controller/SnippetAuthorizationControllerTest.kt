package ingsist.auth.controller

import ingsist.auth.dto.GrantPermissionDto
import ingsist.auth.entity.AuthorizationTypes
import ingsist.auth.entity.SnippetsAuthorization
import ingsist.auth.exceptions.PermissionAlreadyExistsException
import ingsist.auth.exceptions.PermissionNotFoundException
import ingsist.auth.exceptions.UnauthorizedException
import ingsist.auth.service.AuthorizationService
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`
import org.mockito.junit.jupiter.MockitoExtension
import org.springframework.http.HttpStatus
import org.springframework.security.oauth2.jwt.Jwt

@ExtendWith(MockitoExtension::class)
class SnippetAuthorizationControllerTest {
    @Mock
    private lateinit var authorizationService: AuthorizationService

    @InjectMocks
    private lateinit var controller: SnippetAuthorizationController

    private val testJwt =
        Jwt.withTokenValue("test-token")
            .header("alg", "RS256")
            .claim("sub", "user123")
            .build()

    @Test
    fun `grantPermission should return 201 Created with new permission`() {
        val snippetId = "snippet-1"
        val targetUserId = "user456"
        val request = GrantPermissionDto(userId = targetUserId, permission = AuthorizationTypes.READ)
        val expectedPermission =
            SnippetsAuthorization(
                id = "perm-1",
                snippetId = snippetId,
                userId = targetUserId,
                permission = AuthorizationTypes.READ,
            )

        `when`(
            authorizationService.grantPermission(
                targetUserId = targetUserId,
                snippetId = snippetId,
                permissionToGrant = AuthorizationTypes.READ,
                requestingUserId = "user123",
            ),
        ).thenReturn(expectedPermission)

        val response = controller.grantPermission(snippetId, request, testJwt)

        assertEquals(HttpStatus.CREATED, response.statusCode)
        assertEquals(expectedPermission, response.body)
        verify(authorizationService).grantPermission(
            targetUserId = targetUserId,
            snippetId = snippetId,
            permissionToGrant = AuthorizationTypes.READ,
            requestingUserId = "user123",
        )
    }

    @Test
    fun `grantPermission should throw UnauthorizedException when user lacks permission`() {
        val snippetId = "snippet-1"
        val request = GrantPermissionDto(userId = "user456", permission = AuthorizationTypes.READ)

        `when`(
            authorizationService.grantPermission(
                targetUserId = "user456",
                snippetId = snippetId,
                permissionToGrant = AuthorizationTypes.READ,
                requestingUserId = "user123",
            ),
        ).thenThrow(UnauthorizedException("User user123 has no permissions on snippet snippet-1 to grant access."))

        val exception =
            org.junit.jupiter.api.assertThrows<UnauthorizedException> {
                controller.grantPermission(snippetId, request, testJwt)
            }

        assertEquals("User user123 has no permissions on snippet snippet-1 to grant access.", exception.message)
    }

    @Test
    fun `grantPermission should throw PermissionAlreadyExistsException when permission exists`() {
        val snippetId = "snippet-1"
        val request = GrantPermissionDto(userId = "user456", permission = AuthorizationTypes.READ)

        `when`(
            authorizationService.grantPermission(
                targetUserId = "user456",
                snippetId = snippetId,
                permissionToGrant = AuthorizationTypes.READ,
                requestingUserId = "user123",
            ),
        ).thenThrow(PermissionAlreadyExistsException("User user456 already has a permission on snippet snippet-1"))

        val exception =
            org.junit.jupiter.api.assertThrows<PermissionAlreadyExistsException> {
                controller.grantPermission(snippetId, request, testJwt)
            }

        assertEquals("User user456 already has a permission on snippet snippet-1", exception.message)
    }

    @Test
    fun `revokePermission should return 204 No Content`() {
        val snippetId = "snippet-1"
        val targetUserId = "user456"

        val response = controller.revokePermission(snippetId, targetUserId, testJwt)

        assertEquals(HttpStatus.NO_CONTENT, response.statusCode)
        verify(authorizationService).revokePermission(
            targetUserId = targetUserId,
            snippetId = snippetId,
            requestingUserId = "user123",
        )
    }

    @Test
    fun `revokePermission should throw UnauthorizedException when user lacks permission`() {
        val snippetId = "snippet-1"
        val targetUserId = "user456"

        `when`(
            authorizationService.revokePermission(
                targetUserId = targetUserId,
                snippetId = snippetId,
                requestingUserId = "user123",
            ),
        ).thenThrow(UnauthorizedException("User user123 does not have WRITE permission on snippet snippet-1"))

        val exception =
            org.junit.jupiter.api.assertThrows<UnauthorizedException> {
                controller.revokePermission(snippetId, targetUserId, testJwt)
            }

        assertEquals("User user123 does not have WRITE permission on snippet snippet-1", exception.message)
    }

    @Test
    fun `revokePermission should throw PermissionNotFoundException when permission not found`() {
        val snippetId = "snippet-1"
        val targetUserId = "user456"

        `when`(
            authorizationService.revokePermission(
                targetUserId = targetUserId,
                snippetId = snippetId,
                requestingUserId = "user123",
            ),
        ).thenThrow(PermissionNotFoundException("No permission found for user user456 on snippet snippet-1"))

        val exception =
            org.junit.jupiter.api.assertThrows<PermissionNotFoundException> {
                controller.revokePermission(snippetId, targetUserId, testJwt)
            }

        assertEquals("No permission found for user user456 on snippet snippet-1", exception.message)
    }

    @Test
    fun `getPermissionForUserOnSnippet should return permission`() {
        val snippetId = "snippet-1"
        val targetUserId = "user456"
        val expectedPermission =
            SnippetsAuthorization(
                id = "perm-1",
                snippetId = snippetId,
                userId = targetUserId,
                permission = AuthorizationTypes.READ,
            )

        `when`(authorizationService.getPermission(targetUserId, snippetId))
            .thenReturn(expectedPermission)

        val response = controller.getPermissionForUserOnSnippet(snippetId, targetUserId, testJwt)

        assertEquals(HttpStatus.OK, response.statusCode)
        assertEquals(expectedPermission, response.body)
        verify(authorizationService).checkPermission("user123", snippetId, AuthorizationTypes.READ)
    }

    @Test
    fun `getPermissionForUserOnSnippet should throw PermissionNotFoundException when not found`() {
        val snippetId = "snippet-1"
        val targetUserId = "user456"

        `when`(authorizationService.getPermission(targetUserId, snippetId))
            .thenThrow(PermissionNotFoundException("No permission found for user user456 on snippet snippet-1"))

        val exception =
            org.junit.jupiter.api.assertThrows<PermissionNotFoundException> {
                controller.getPermissionForUserOnSnippet(snippetId, targetUserId, testJwt)
            }

        assertEquals("No permission found for user user456 on snippet snippet-1", exception.message)
        verify(authorizationService).checkPermission("user123", snippetId, AuthorizationTypes.READ)
    }

    @Test
    fun `getPermissionForUserOnSnippet should throw UnauthorizedException when user lacks READ permission`() {
        val snippetId = "snippet-1"
        val targetUserId = "user456"

        `when`(authorizationService.checkPermission("user123", snippetId, AuthorizationTypes.READ))
            .thenThrow(UnauthorizedException("User user123 does not have READ permission on snippet snippet-1"))

        val exception =
            org.junit.jupiter.api.assertThrows<UnauthorizedException> {
                controller.getPermissionForUserOnSnippet(snippetId, targetUserId, testJwt)
            }

        assertEquals("User user123 does not have READ permission on snippet snippet-1", exception.message)
    }

    @Test
    fun `getPermissionsForSnippet should return list of permissions`() {
        val snippetId = "snippet-1"
        val expectedPermissions =
            listOf(
                SnippetsAuthorization(
                    id = "perm-1",
                    snippetId = snippetId,
                    userId = "user456",
                    permission = AuthorizationTypes.READ,
                ),
                SnippetsAuthorization(
                    id = "perm-2",
                    snippetId = snippetId,
                    userId = "user789",
                    permission = AuthorizationTypes.WRITE,
                ),
            )

        `when`(authorizationService.getPermissionsForSnippet(snippetId, "user123"))
            .thenReturn(expectedPermissions)

        val response = controller.getPermissionsForSnippet(snippetId, testJwt)

        assertEquals(HttpStatus.OK, response.statusCode)
        assertEquals(expectedPermissions, response.body)
    }

    @Test
    fun `getPermissionsForSnippet should throw UnauthorizedException when user lacks WRITE permission`() {
        val snippetId = "snippet-1"

        `when`(authorizationService.getPermissionsForSnippet(snippetId, "user123"))
            .thenThrow(UnauthorizedException("User user123 does not have WRITE permission on snippet snippet-1"))

        val exception =
            org.junit.jupiter.api.assertThrows<UnauthorizedException> {
                controller.getPermissionsForSnippet(snippetId, testJwt)
            }

        assertEquals("User user123 does not have WRITE permission on snippet snippet-1", exception.message)
    }
}
