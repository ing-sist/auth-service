package ingsist.auth.controller

import ingsist.auth.entity.AuthorizationTypes
import ingsist.auth.entity.SnippetsAuthorization
import ingsist.auth.exceptions.UnauthorizedException
import ingsist.auth.service.UserAuthorizationService
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
class UserAuthorizationControllerTest {
    @Mock
    private lateinit var userAuthorizationService: UserAuthorizationService

    @InjectMocks
    private lateinit var controller: UserAuthorizationController

    private val testJwt =
        Jwt.withTokenValue("test-token")
            .header("alg", "RS256")
            .claim("sub", "user123")
            .build()

    @Test
    fun `getPermissionsForUser should return list of permissions when user requests own permissions`() {
        val userId = "user123"
        val expectedPermissions =
            listOf(
                SnippetsAuthorization(
                    id = "perm-1",
                    snippetId = "snippet-1",
                    userId = userId,
                    permission = AuthorizationTypes.READ,
                ),
                SnippetsAuthorization(
                    id = "perm-2",
                    snippetId = "snippet-2",
                    userId = userId,
                    permission = AuthorizationTypes.WRITE,
                ),
            )

        `when`(userAuthorizationService.getPermissionsForUser(userId))
            .thenReturn(expectedPermissions)

        val response = controller.getPermissionsForUser(userId, testJwt)

        assertEquals(HttpStatus.OK, response.statusCode)
        assertEquals(expectedPermissions, response.body)
        verify(userAuthorizationService).getPermissionsForUser(userId)
    }

    @Test
    fun `getPermissionsForUser should return empty list when user has no permissions`() {
        val userId = "user123"
        val expectedPermissions = emptyList<SnippetsAuthorization>()

        `when`(userAuthorizationService.getPermissionsForUser(userId))
            .thenReturn(expectedPermissions)

        val response = controller.getPermissionsForUser(userId, testJwt)

        assertEquals(HttpStatus.OK, response.statusCode)
        assertEquals(expectedPermissions, response.body)
    }

    @Test
    fun `getPermissionsForUser should throw UnauthorizedException when user requests another user's permissions`() {
        val requestedUserId = "user456"

        val exception =
            org.junit.jupiter.api.assertThrows<UnauthorizedException> {
                controller.getPermissionsForUser(requestedUserId, testJwt)
            }

        assertEquals("No puedes ver los permisos de otro usuario.", exception.message)
    }

    @Test
    fun `getPermissionsForUser should allow user to view their own permissions even with different casing`() {
        val userId = "user123"
        val expectedPermissions =
            listOf(
                SnippetsAuthorization(
                    id = "perm-1",
                    snippetId = "snippet-1",
                    userId = userId,
                    permission = AuthorizationTypes.READ,
                ),
            )

        `when`(userAuthorizationService.getPermissionsForUser(userId))
            .thenReturn(expectedPermissions)

        val response = controller.getPermissionsForUser(userId, testJwt)

        assertEquals(HttpStatus.OK, response.statusCode)
        assertEquals(expectedPermissions, response.body)
    }
}
