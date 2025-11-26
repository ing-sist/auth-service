package ingsist.auth.controller

import ingsist.auth.dto.GrantPermissionDto
import ingsist.auth.entity.AuthorizationTypes
import ingsist.auth.entity.AuthorizationTypes.READ
import ingsist.auth.entity.AuthorizationTypes.WRITE
import ingsist.auth.entity.SnippetsAuthorization
import ingsist.auth.exceptions.CannotRevokeLastWritePermissionException
import ingsist.auth.exceptions.PermissionAlreadyExistsException
import ingsist.auth.exceptions.PermissionNotFoundException
import ingsist.auth.exceptions.UnauthorizedException
import ingsist.auth.service.AuthorizationService
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.Mockito.doNothing
import org.mockito.Mockito.doThrow
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`
import org.mockito.junit.jupiter.MockitoExtension
import org.springframework.http.HttpStatus
import org.springframework.security.oauth2.jwt.Jwt

@ExtendWith(MockitoExtension::class)
@DisplayName("SnippetAuthorizationController")
class SnippetAuthorizationControllerTest {
    @Mock
    private lateinit var authorizationService: AuthorizationService

    @InjectMocks
    private lateinit var controller: SnippetAuthorizationController

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

        fun grantReadRequest(userId: String = TARGET_USER_ID) = GrantPermissionDto(userId = userId, permission = READ)

        fun grantWriteRequest(userId: String = TARGET_USER_ID) = GrantPermissionDto(userId = userId, permission = WRITE)
    }

    @Nested
    @DisplayName("POST /snippets/{snippetId}/permissions - grantPermission")
    inner class GrantPermissionEndpoint {
        @Nested
        @DisplayName("successful scenarios")
        inner class SuccessScenarios {
            @Test
            @DisplayName("should return 201 CREATED with READ permission when granted successfully")
            fun `returns created with read permission`() {
                // Given
                val request = grantReadRequest()
                val expectedPermission = aPermission(permission = READ)
                givenGrantPermissionReturns(expectedPermission)

                // When
                val response = controller.grantPermission(SNIPPET_ID, request, ownerJwt)

                // Then
                assertEquals(HttpStatus.CREATED, response.statusCode)
                assertNotNull(response.body)
                assertEquals(expectedPermission, response.body)
                assertEquals(READ, response.body?.permission)
            }

            @Test
            @DisplayName("should return 201 CREATED with WRITE permission when granted successfully")
            fun `returns created with write permission`() {
                val request = grantWriteRequest()
                val expectedPermission = aPermission(permission = WRITE)

                `when`(
                    authorizationService.grantPermission(
                        targetUserId = TARGET_USER_ID,
                        snippetId = SNIPPET_ID,
                        permissionToGrant = WRITE,
                        requestingUserId = OWNER_ID,
                    ),
                ).thenReturn(expectedPermission)

                val response = controller.grantPermission(SNIPPET_ID, request, ownerJwt)

                assertEquals(HttpStatus.CREATED, response.statusCode)
                assertEquals(WRITE, response.body?.permission)
            }

            @Test
            @DisplayName("should correctly extract userId from JWT token")
            fun `extracts user id from jwt`() {
                val request = grantReadRequest()
                val expectedPermission = aPermission()
                givenGrantPermissionReturns(expectedPermission)

                controller.grantPermission(SNIPPET_ID, request, ownerJwt)

                verify(authorizationService).grantPermission(
                    targetUserId = TARGET_USER_ID,
                    snippetId = SNIPPET_ID,
                    permissionToGrant = READ,
                    requestingUserId = OWNER_ID,
                )
            }
        }

        @Nested
        @DisplayName("error scenarios")
        inner class ErrorScenarios {
            @Test
            @DisplayName("should throw UnauthorizedException when user lacks permission to grant")
            fun `throws unauthorized for non-owner`() {
                val request = grantReadRequest()
                givenGrantPermissionThrows(
                    UnauthorizedException("User $OWNER_ID has no permissions on snippet $SNIPPET_ID to grant access."),
                )

                val exception =
                    assertThrows<UnauthorizedException> {
                        controller.grantPermission(SNIPPET_ID, request, ownerJwt)
                    }

                assertEquals(
                    "User $OWNER_ID has no permissions on snippet $SNIPPET_ID to grant access.",
                    exception.message,
                )
            }

            @Test
            @DisplayName("should throw UnauthorizedException when user only has READ permission")
            fun `throws unauthorized for read-only user`() {
                val request = grantReadRequest()
                givenGrantPermissionThrows(
                    UnauthorizedException("User $OWNER_ID does not have WRITE permission to grant access."),
                )

                val exception =
                    assertThrows<UnauthorizedException> {
                        controller.grantPermission(SNIPPET_ID, request, ownerJwt)
                    }

                assertEquals(
                    "User $OWNER_ID does not have WRITE permission to grant access.",
                    exception.message,
                )
            }

            @Test
            @DisplayName("should throw PermissionAlreadyExistsException when target already has permission")
            fun `throws conflict for duplicate permission`() {
                val request = grantReadRequest()
                val message = "User $TARGET_USER_ID already has a permission on snippet $SNIPPET_ID"
                givenGrantPermissionThrows(
                    PermissionAlreadyExistsException(message),
                )

                val exception =
                    assertThrows<PermissionAlreadyExistsException> {
                        controller.grantPermission(SNIPPET_ID, request, ownerJwt)
                    }

                assertEquals(
                    "User $TARGET_USER_ID already has a permission on snippet $SNIPPET_ID",
                    exception.message,
                )
            }
        }
    }

    @Nested
    @DisplayName("DELETE /snippets/{snippetId}/permissions/{userId} - revokePermission")
    inner class RevokePermissionEndpoint {
        @Nested
        @DisplayName("successful scenarios")
        inner class SuccessScenarios {
            @Test
            @DisplayName("should return 204 NO_CONTENT when permission revoked successfully")
            fun `returns no content on success`() {
                doNothing().`when`(authorizationService).revokePermission(
                    targetUserId = TARGET_USER_ID,
                    snippetId = SNIPPET_ID,
                    requestingUserId = OWNER_ID,
                )

                val response = controller.revokePermission(SNIPPET_ID, TARGET_USER_ID, ownerJwt)

                assertEquals(HttpStatus.NO_CONTENT, response.statusCode)
                assertNull(response.body)
            }

            @Test
            @DisplayName("should correctly delegate to service with all parameters")
            fun `delegates correctly to service`() {
                doNothing().`when`(authorizationService).revokePermission(
                    targetUserId = TARGET_USER_ID,
                    snippetId = SNIPPET_ID,
                    requestingUserId = OWNER_ID,
                )

                controller.revokePermission(SNIPPET_ID, TARGET_USER_ID, ownerJwt)

                verify(authorizationService).revokePermission(
                    targetUserId = TARGET_USER_ID,
                    snippetId = SNIPPET_ID,
                    requestingUserId = OWNER_ID,
                )
            }
        }

        @Nested
        @DisplayName("error scenarios")
        inner class ErrorScenarios {
            @Test
            @DisplayName("should throw UnauthorizedException when user lacks WRITE permission")
            fun `throws unauthorized for non-writer`() {
                doThrow(UnauthorizedException("User $OWNER_ID does not have WRITE permission on snippet $SNIPPET_ID"))
                    .`when`(authorizationService).revokePermission(
                        targetUserId = TARGET_USER_ID,
                        snippetId = SNIPPET_ID,
                        requestingUserId = OWNER_ID,
                    )

                val exception =
                    assertThrows<UnauthorizedException> {
                        controller.revokePermission(SNIPPET_ID, TARGET_USER_ID, ownerJwt)
                    }

                assertEquals(
                    "User $OWNER_ID does not have WRITE permission on snippet $SNIPPET_ID",
                    exception.message,
                )
            }

            @Test
            @DisplayName("should throw PermissionNotFoundException when target permission does not exist")
            fun `throws not found for missing permission`() {
                val message = "No permission found for user $TARGET_USER_ID on snippet $SNIPPET_ID"
                doThrow(PermissionNotFoundException(message))
                    .`when`(authorizationService).revokePermission(
                        targetUserId = TARGET_USER_ID,
                        snippetId = SNIPPET_ID,
                        requestingUserId = OWNER_ID,
                    )

                val exception =
                    assertThrows<PermissionNotFoundException> {
                        controller.revokePermission(SNIPPET_ID, TARGET_USER_ID, ownerJwt)
                    }

                assertEquals(
                    "No permission found for user $TARGET_USER_ID on snippet $SNIPPET_ID",
                    exception.message,
                )
            }

            @Test
            @DisplayName("should throw CannotRevokeLastWritePermissionException when revoking last writer")
            fun `throws bad request for last writer`() {
                val message = "Cannot revoke the last WRITE permission for snippet $SNIPPET_ID"
                doThrow(CannotRevokeLastWritePermissionException(message))
                    .`when`(authorizationService).revokePermission(
                        targetUserId = TARGET_USER_ID,
                        snippetId = SNIPPET_ID,
                        requestingUserId = OWNER_ID,
                    )

                val exception =
                    assertThrows<CannotRevokeLastWritePermissionException> {
                        controller.revokePermission(SNIPPET_ID, TARGET_USER_ID, ownerJwt)
                    }

                assertEquals(
                    "Cannot revoke the last WRITE permission for snippet $SNIPPET_ID",
                    exception.message,
                )
            }
        }
    }

    @Nested
    @DisplayName("GET /snippets/{snippetId}/permissions/{userId} - getPermissionForUserOnSnippet")
    inner class GetPermissionForUserEndpoint {
        @Nested
        @DisplayName("successful scenarios")
        inner class SuccessScenarios {
            @Test
            @DisplayName("should return 200 OK with permission when found")
            fun `returns ok with permission`() {
                val expectedPermission = aPermission()
                doNothing().`when`(authorizationService).checkPermission(OWNER_ID, SNIPPET_ID, READ)
                `when`(authorizationService.getPermission(TARGET_USER_ID, SNIPPET_ID))
                    .thenReturn(expectedPermission)

                val response = controller.getPermissionForUserOnSnippet(SNIPPET_ID, TARGET_USER_ID, ownerJwt)

                assertEquals(HttpStatus.OK, response.statusCode)
                assertEquals(expectedPermission, response.body)
            }

            @Test
            @DisplayName("should verify requesting user has READ permission before returning")
            fun `verifies read permission first`() {
                val expectedPermission = aPermission()
                doNothing().`when`(authorizationService).checkPermission(OWNER_ID, SNIPPET_ID, READ)
                `when`(authorizationService.getPermission(TARGET_USER_ID, SNIPPET_ID))
                    .thenReturn(expectedPermission)

                controller.getPermissionForUserOnSnippet(SNIPPET_ID, TARGET_USER_ID, ownerJwt)

                verify(authorizationService).checkPermission(OWNER_ID, SNIPPET_ID, READ)
            }
        }

        @Nested
        @DisplayName("error scenarios")
        inner class ErrorScenarios {
            @Test
            @DisplayName("should throw PermissionNotFoundException when target permission not found")
            fun `throws not found for missing permission`() {
                val message = "No permission found for user $TARGET_USER_ID on snippet $SNIPPET_ID"
                doNothing().`when`(authorizationService).checkPermission(OWNER_ID, SNIPPET_ID, READ)
                `when`(authorizationService.getPermission(TARGET_USER_ID, SNIPPET_ID))
                    .thenThrow(PermissionNotFoundException(message))

                val exception =
                    assertThrows<PermissionNotFoundException> {
                        controller.getPermissionForUserOnSnippet(SNIPPET_ID, TARGET_USER_ID, ownerJwt)
                    }

                assertEquals(
                    "No permission found for user $TARGET_USER_ID on snippet $SNIPPET_ID",
                    exception.message,
                )
            }

            @Test
            @DisplayName("should throw UnauthorizedException when requesting user lacks READ permission")
            fun `throws unauthorized for non-reader`() {
                doThrow(UnauthorizedException("User $OWNER_ID does not have READ permission on snippet $SNIPPET_ID"))
                    .`when`(authorizationService).checkPermission(OWNER_ID, SNIPPET_ID, READ)

                val exception =
                    assertThrows<UnauthorizedException> {
                        controller.getPermissionForUserOnSnippet(SNIPPET_ID, TARGET_USER_ID, ownerJwt)
                    }

                assertEquals(
                    "User $OWNER_ID does not have READ permission on snippet $SNIPPET_ID",
                    exception.message,
                )
            }
        }
    }

    @Nested
    @DisplayName("GET /snippets/{snippetId}/permissions - getPermissionsForSnippet")
    inner class GetPermissionsForSnippetEndpoint {
        @Nested
        @DisplayName("successful scenarios")
        inner class SuccessScenarios {
            @Test
            @DisplayName("should return 200 OK with list of permissions")
            fun `returns ok with permissions list`() {
                val permissions =
                    listOf(
                        aPermission(id = "perm-1", userId = OWNER_ID, permission = WRITE),
                        aPermission(id = "perm-2", userId = TARGET_USER_ID, permission = READ),
                    )
                `when`(authorizationService.getPermissionsForSnippet(SNIPPET_ID, OWNER_ID))
                    .thenReturn(permissions)

                val response = controller.getPermissionsForSnippet(SNIPPET_ID, ownerJwt)

                assertEquals(HttpStatus.OK, response.statusCode)
                assertEquals(2, response.body?.size)
                assertEquals(permissions, response.body)
            }

            @Test
            @DisplayName("should return 200 OK with empty list when no permissions exist")
            fun `returns ok with empty list`() {
                `when`(authorizationService.getPermissionsForSnippet(SNIPPET_ID, OWNER_ID))
                    .thenReturn(emptyList())

                val response = controller.getPermissionsForSnippet(SNIPPET_ID, ownerJwt)

                assertEquals(HttpStatus.OK, response.statusCode)
                assertEquals(0, response.body?.size)
            }
        }

        @Nested
        @DisplayName("error scenarios")
        inner class ErrorScenarios {
            @Test
            @DisplayName("should throw UnauthorizedException when user lacks WRITE permission")
            fun `throws unauthorized for non-writer`() {
                val message = "User $OWNER_ID does not have WRITE permission on snippet $SNIPPET_ID"
                `when`(authorizationService.getPermissionsForSnippet(SNIPPET_ID, OWNER_ID))
                    .thenThrow(UnauthorizedException(message))

                val exception =
                    assertThrows<UnauthorizedException> {
                        controller.getPermissionsForSnippet(SNIPPET_ID, ownerJwt)
                    }

                assertEquals(
                    "User $OWNER_ID does not have WRITE permission on snippet $SNIPPET_ID",
                    exception.message,
                )
            }
        }
    }

    // Helper methods - DSL Style
    private fun givenGrantPermissionReturns(permission: SnippetsAuthorization) {
        `when`(
            authorizationService.grantPermission(
                targetUserId = TARGET_USER_ID,
                snippetId = SNIPPET_ID,
                permissionToGrant = permission.permission,
                requestingUserId = OWNER_ID,
            ),
        ).thenReturn(permission)
    }

    private fun givenGrantPermissionThrows(exception: RuntimeException) {
        `when`(
            authorizationService.grantPermission(
                targetUserId = TARGET_USER_ID,
                snippetId = SNIPPET_ID,
                permissionToGrant = READ,
                requestingUserId = OWNER_ID,
            ),
        ).thenThrow(exception)
    }
}
