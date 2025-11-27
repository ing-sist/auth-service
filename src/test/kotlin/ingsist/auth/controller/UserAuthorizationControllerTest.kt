package ingsist.auth.controller

import ingsist.auth.dto.SnippetAuthorizationDto
import ingsist.auth.entity.AuthorizationTypes.READ
import ingsist.auth.entity.AuthorizationTypes.WRITE
import ingsist.auth.exceptions.UnauthorizedException
import ingsist.auth.service.UserAuthorizationService
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.Mockito.never
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`
import org.mockito.junit.jupiter.MockitoExtension
import org.mockito.kotlin.any
import org.springframework.http.HttpStatus
import org.springframework.security.oauth2.jwt.Jwt

@ExtendWith(MockitoExtension::class)
@DisplayName("UserAuthorizationController")
class UserAuthorizationControllerTest {
    @Mock
    private lateinit var userAuthorizationService: UserAuthorizationService

    @InjectMocks
    private lateinit var controller: UserAuthorizationController

    companion object {
        const val USER_ID = "user-123"
        const val OTHER_USER_ID = "other-user-456"

        fun jwtForUser(userId: String): Jwt =
            Jwt.withTokenValue("test-token")
                .header("alg", "RS256")
                .claim("sub", userId)
                .build()

        val userJwt = jwtForUser(USER_ID)
        val otherUserJwt = jwtForUser(OTHER_USER_ID)

        fun aPermissionDto(
            id: String,
            snippetId: String,
            userId: String = USER_ID,
            userEmail: String = "user@example.com",
            permission: ingsist.auth.entity.AuthorizationTypes = READ,
        ) = SnippetAuthorizationDto(
            id = id,
            snippetId = snippetId,
            userId = userId,
            userEmail = userEmail,
            permission = permission,
        )

        fun multiplePermissions(userId: String = USER_ID) =
            listOf(
                aPermissionDto(id = "perm-1", snippetId = "snippet-1", userId = userId, permission = READ),
                aPermissionDto(id = "perm-2", snippetId = "snippet-2", userId = userId, permission = WRITE),
            )
    }

    @Nested
    @DisplayName("GET /users/{userId}/permissions - getPermissionsForUser")
    inner class GetPermissionsForUserEndpoint {
        @Nested
        @DisplayName("when user requests their own permissions")
        inner class OwnPermissions {
            @Test
            @DisplayName("should return 200 OK with list of permissions")
            fun `returns ok with permissions list`() {
                // Given
                val expectedPermissions = multiplePermissions()
                givenUserPermissions(USER_ID, expectedPermissions)

                // When
                val response = controller.getPermissionsForUser(USER_ID, userJwt)

                // Then
                assertEquals(HttpStatus.OK, response.statusCode)
                assertEquals(expectedPermissions, response.body)
                assertEquals(2, response.body?.size)
            }

            @Test
            @DisplayName("should return 200 OK with empty list when no permissions")
            fun `returns ok with empty list`() {
                givenUserPermissions(USER_ID, emptyList())

                val response = controller.getPermissionsForUser(USER_ID, userJwt)

                assertEquals(HttpStatus.OK, response.statusCode)
                assertTrue(response.body?.isEmpty() == true)
            }

            @Test
            @DisplayName("should correctly delegate to service")
            fun `delegates to service correctly`() {
                givenUserPermissions(USER_ID, emptyList())

                controller.getPermissionsForUser(USER_ID, userJwt)

                verify(userAuthorizationService).getPermissionsForUser(USER_ID)
            }

            @Test
            @DisplayName("should return single permission when user has one")
            fun `returns single permission`() {
                val singlePermission =
                    listOf(
                        aPermissionDto(id = "perm-1", snippetId = "snippet-1", permission = WRITE),
                    )
                givenUserPermissions(USER_ID, singlePermission)

                val response = controller.getPermissionsForUser(USER_ID, userJwt)

                assertEquals(1, response.body?.size)
                assertEquals(WRITE, response.body?.get(0)?.permission)
            }

            @Test
            @DisplayName("should return permissions with mixed types")
            fun `returns mixed permission types`() {
                val mixedPermissions =
                    listOf(
                        aPermissionDto(id = "perm-1", snippetId = "snippet-1", permission = READ),
                        aPermissionDto(id = "perm-2", snippetId = "snippet-2", permission = WRITE),
                        aPermissionDto(id = "perm-3", snippetId = "snippet-3", permission = READ),
                    )
                givenUserPermissions(USER_ID, mixedPermissions)

                val response = controller.getPermissionsForUser(USER_ID, userJwt)

                assertEquals(3, response.body?.size)
            }
        }

        @Nested
        @DisplayName("when user requests another user's permissions")
        inner class OtherUserPermissions {
            @Test
            @DisplayName("should throw UnauthorizedException")
            fun `throws unauthorized exception`() {
                // When trying to access another user's permissions
                val exception =
                    assertThrows<UnauthorizedException> {
                        controller.getPermissionsForUser(USER_ID, otherUserJwt)
                    }

                // Then
                assertEquals("No puedes ver los permisos de otro usuario.", exception.message)
                verify(userAuthorizationService, never()).getPermissionsForUser(any())
            }

            @Test
            @DisplayName("should not call service when unauthorized")
            fun `does not call service`() {
                assertThrows<UnauthorizedException> {
                    controller.getPermissionsForUser(USER_ID, otherUserJwt)
                }

                verify(userAuthorizationService, never()).getPermissionsForUser(USER_ID)
            }

            @Test
            @DisplayName("should reject access for any different user ID")
            fun `rejects any different user`() {
                val differentUserJwt = jwtForUser("completely-different-user")

                val exception =
                    assertThrows<UnauthorizedException> {
                        controller.getPermissionsForUser(USER_ID, differentUserJwt)
                    }

                assertEquals("No puedes ver los permisos de otro usuario.", exception.message)
            }
        }

        @Nested
        @DisplayName("JWT extraction")
        inner class JwtExtraction {
            @Test
            @DisplayName("should correctly extract user ID from JWT subject claim")
            fun `extracts user id from jwt subject`() {
                val customUserId = "custom-user-id-789"
                val customJwt = jwtForUser(customUserId)
                givenUserPermissions(customUserId, emptyList())

                controller.getPermissionsForUser(customUserId, customJwt)

                verify(userAuthorizationService).getPermissionsForUser(customUserId)
            }

            @Test
            @DisplayName("should match exact user ID from JWT")
            fun `matches exact user id`() {
                val jwt = jwtForUser("exact-match-user")
                givenUserPermissions("exact-match-user", emptyList())

                val response = controller.getPermissionsForUser("exact-match-user", jwt)

                assertEquals(HttpStatus.OK, response.statusCode)
            }
        }
    }

    // Helper methods - DSL Style
    private fun givenUserPermissions(
        userId: String,
        permissions: List<SnippetAuthorizationDto>,
    ) {
        `when`(userAuthorizationService.getPermissionsForUser(userId)).thenReturn(permissions)
    }
}
