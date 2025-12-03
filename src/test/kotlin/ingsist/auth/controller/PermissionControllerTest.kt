package ingsist.auth.controller

import ingsist.auth.dto.GrantPermissionDto
import ingsist.auth.dto.SharedSnippetDto
import ingsist.auth.entity.AuthorizationTypes
import ingsist.auth.entity.AuthorizationTypes.READ
import ingsist.auth.entity.AuthorizationTypes.WRITE
import ingsist.auth.entity.SnippetsAuthorization
import ingsist.auth.exceptions.UnauthorizedException
import ingsist.auth.service.PermissionService
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.Mockito.doNothing
import org.mockito.Mockito.never
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.any
import org.springframework.http.HttpStatus
import org.springframework.security.oauth2.jwt.Jwt

@ExtendWith(MockitoExtension::class)
@DisplayName("PermissionController")
class PermissionControllerTest {
    @Mock
    private lateinit var permissionService: PermissionService

    @InjectMocks
    private lateinit var controller: PermissionController

    companion object {
        const val OWNER_ID = "owner-user-123"
        const val TARGET_USER_ID = "target-user-456"
        const val SNIPPET_ID = "snippet-abc-123"

        fun jwtForUser(userId: String): Jwt =
            Jwt.withTokenValue("test-token")
                .header("alg", "RS256")
                .claim("sub", userId)
                .build()

        val ownerJwt = jwtForUser(OWNER_ID)
        val targetJwt = jwtForUser(TARGET_USER_ID)

        fun aPermission(
            id: String = "perm-1",
            snippetId: String = SNIPPET_ID,
            userId: String = TARGET_USER_ID,
            permission: AuthorizationTypes = READ,
        ) = SnippetsAuthorization(
            id = id,
            snippetId = snippetId,
            userId = userId,
            permission = permission,
        )

        fun aPermissionDto(
            id: String,
            snippetId: String,
            userId: String = TARGET_USER_ID,
            userEmail: String = "user@example.com",
            permission: AuthorizationTypes = READ,
        ) = SharedSnippetDto(
            id = id,
            snippetId = snippetId,
            userId = userId,
            userEmail = userEmail,
            permission = permission,
        )

        fun grantReadRequest(
            userId: String = TARGET_USER_ID,
            snippetId: String = SNIPPET_ID,
        ) = GrantPermissionDto(userId = userId, permission = READ, snippetId = snippetId)

        fun grantWriteRequest(
            userId: String = TARGET_USER_ID,
            snippetId: String = SNIPPET_ID,
        ) = GrantPermissionDto(userId = userId, permission = WRITE, snippetId = snippetId)
    }

    @Nested
    @DisplayName("POST /permissions - grantPermission")
    inner class GrantPermissionEndpoint {
        @Test
        @DisplayName("should return 200 OK with permission when granted successfully")
        fun `returns ok with permission`() {
            val request = grantReadRequest()
            val expectedPermission = aPermission(permission = READ)
            `when`(permissionService.createAuthorization(request, OWNER_ID)).thenReturn(expectedPermission)

            val response = controller.grantPermission(request, ownerJwt)

            assertEquals(HttpStatus.OK, response.statusCode)
            assertEquals(expectedPermission, response.body)
        }

        @Test
        @DisplayName("should throw UnauthorizedException when service throws")
        fun `throws unauthorized when service throws`() {
            val request = grantReadRequest()
            `when`(permissionService.createAuthorization(request, OWNER_ID))
                .thenThrow(UnauthorizedException("Unauthorized"))

            assertThrows<UnauthorizedException> {
                controller.grantPermission(request, ownerJwt)
            }
        }
    }

    @Nested
    @DisplayName("GET /permissions/user/{userId} - getSnippetsForUser")
    inner class GetSnippetsForUserEndpoint {
        @Test
        @DisplayName("should return 200 OK with list of permissions for own user")
        fun `returns ok with permissions list`() {
            val expectedPermissions =
                listOf(
                    aPermissionDto("1", "s1"),
                    aPermissionDto("2", "s2"),
                )
            `when`(permissionService.getPermissionsForUser(OWNER_ID)).thenReturn(expectedPermissions)

            val response = controller.getSnippetsForUser(OWNER_ID, ownerJwt)

            assertEquals(HttpStatus.OK, response.statusCode)
            assertEquals(expectedPermissions, response.body)
        }

        @Test
        @DisplayName("should throw UnauthorizedException when requesting other user permissions")
        fun `throws unauthorized for other user`() {
            assertThrows<UnauthorizedException> {
                controller.getSnippetsForUser(TARGET_USER_ID, ownerJwt)
            }
            verify(permissionService, never()).getPermissionsForUser(any())
        }
    }

    @Nested
    @DisplayName("GET /permissions/snippet/{snippetId} - hasAccess")
    inner class HasAccessEndpoint {
        @Test
        @DisplayName("should return 200 OK with true when user has permission")
        fun `returns true when user has permission`() {
            `when`(permissionService.hasPermission(OWNER_ID, SNIPPET_ID, READ)).thenReturn(true)

            val response = controller.hasAccess(SNIPPET_ID, READ, ownerJwt)

            assertEquals(HttpStatus.OK, response.statusCode)
            assertEquals(true, response.body)
        }

        @Test
        @DisplayName("should return 200 OK with false when user lacks permission")
        fun `returns false when user lacks permission`() {
            `when`(permissionService.hasPermission(OWNER_ID, SNIPPET_ID, WRITE)).thenReturn(false)

            val response = controller.hasAccess(SNIPPET_ID, WRITE, ownerJwt)

            assertEquals(HttpStatus.OK, response.statusCode)
            assertEquals(false, response.body)
        }
    }

    @Nested
    @DisplayName("DELETE /permissions/snippet/{snippetId} - deleteSnippetPermissions")
    inner class DeleteSnippetPermissionsEndpoint {
        @Test
        @DisplayName("should return 204 No Content on success")
        fun `returns no content on success`() {
            doNothing().`when`(permissionService).deleteSnippet(SNIPPET_ID, OWNER_ID)

            val response = controller.deleteSnippetPermissions(SNIPPET_ID, ownerJwt)

            assertEquals(HttpStatus.NO_CONTENT, response.statusCode)
            verify(permissionService).deleteSnippet(SNIPPET_ID, OWNER_ID)
        }
    }
}
