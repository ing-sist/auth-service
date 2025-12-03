package ingsist.auth.service

import ingsist.auth.entity.AuthorizationTypes
import ingsist.auth.entity.AuthorizationTypes.READ
import ingsist.auth.entity.AuthorizationTypes.WRITE
import ingsist.auth.entity.SnippetsAuthorization
import ingsist.auth.exceptions.PermissionAlreadyExistsException
import ingsist.auth.exceptions.UnauthorizedException
import ingsist.auth.repository.SnippetAuthorizationRepository
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
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
import java.util.Optional

@ExtendWith(MockitoExtension::class)
@DisplayName("PermissionService")
class PermissionServiceTest {
    @Mock
    private lateinit var repository: SnippetAuthorizationRepository

    @Mock
    private lateinit var auth0ManagementService: Auth0ManagementService

    @InjectMocks
    private lateinit var service: PermissionService

    // Test Data Builders - DSL Style
    companion object {
        const val OWNER_ID = "owner-user-123"
        const val TARGET_USER_ID = "target-user-456"
        const val ANOTHER_USER_ID = "another-user-789"
        const val SNIPPET_ID = "snippet-abc-123"

        fun aPermission(
            id: String? = "perm-1",
            userId: String = OWNER_ID,
            snippetId: String = SNIPPET_ID,
            permission: AuthorizationTypes = WRITE,
        ) = SnippetsAuthorization(
            id = id,
            userId = userId,
            snippetId = snippetId,
            permission = permission,
        )

        fun ownerPermission(snippetId: String = SNIPPET_ID) =
            aPermission(
                id = "owner-perm",
                userId = OWNER_ID,
                snippetId = snippetId,
                permission = WRITE,
            )

        fun readerPermission(
            userId: String = TARGET_USER_ID,
            snippetId: String = SNIPPET_ID,
        ) = aPermission(
            id = "reader-perm",
            userId = userId,
            snippetId = snippetId,
            permission = READ,
        )
    }

    @Nested
    @DisplayName("grantPermission")
    inner class GrantPermissionTests {
        @Nested
        @DisplayName("when granting permission on a new snippet")
        inner class NewSnippetScenarios {
            @Test
            @DisplayName("should create WRITE permission for first user on new snippet")
            fun `creates write permission for first user`() {
                // Given: no existing permissions on snippet
                givenNoPermissionsExist()
                givenSnippetHasNoPermissions()
                givenSaveReturnsInput()

                // When: user grants WRITE permission to target user
                val result =
                    service.grantPermission(
                        targetUserId = TARGET_USER_ID,
                        snippetId = SNIPPET_ID,
                        permissionToGrant = WRITE,
                        requestingUserId = OWNER_ID,
                    )

                // Then: permission is created with correct data
                assertNotNull(result)
                assertEquals(TARGET_USER_ID, result.userId)
                assertEquals(SNIPPET_ID, result.snippetId)
                assertEquals(WRITE, result.permission)
                verify(repository).save(any())
            }

            @Test
            @DisplayName("should create READ permission for first user on new snippet")
            fun `creates read permission for first user`() {
                givenNoPermissionsExist()
                givenSnippetHasNoPermissions()
                givenSaveReturnsInput()

                val result =
                    service.grantPermission(
                        targetUserId = TARGET_USER_ID,
                        snippetId = SNIPPET_ID,
                        permissionToGrant = READ,
                        requestingUserId = OWNER_ID,
                    )

                assertEquals(READ, result.permission)
            }
        }

        @Nested
        @DisplayName("when owner grants permission")
        inner class OwnerGrantsPermission {
            @Test
            @DisplayName("should allow WRITE owner to grant READ permission")
            fun `owner can grant read permission`() {
                givenUserHasPermission(OWNER_ID, ownerPermission())
                givenUserHasNoPermission(TARGET_USER_ID)
                givenSaveReturnsInput()

                val result =
                    service.grantPermission(
                        targetUserId = TARGET_USER_ID,
                        snippetId = SNIPPET_ID,
                        permissionToGrant = READ,
                        requestingUserId = OWNER_ID,
                    )

                assertNotNull(result)
                assertEquals(TARGET_USER_ID, result.userId)
                assertEquals(READ, result.permission)
            }

            @Test
            @DisplayName("should allow WRITE owner to grant WRITE permission")
            fun `owner can grant write permission`() {
                givenUserHasPermission(OWNER_ID, ownerPermission())
                givenUserHasNoPermission(TARGET_USER_ID)
                givenSaveReturnsInput()

                val result =
                    service.grantPermission(
                        targetUserId = TARGET_USER_ID,
                        snippetId = SNIPPET_ID,
                        permissionToGrant = WRITE,
                        requestingUserId = OWNER_ID,
                    )

                assertEquals(WRITE, result.permission)
            }
        }

        @Nested
        @DisplayName("when user lacks permission to grant")
        inner class UnauthorizedGrantScenarios {
            @Test
            @DisplayName("should reject when user has no permission on existing snippet")
            fun `rejects when user has no permission`() {
                givenUserHasNoPermission(OWNER_ID)
                givenSnippetHasExistingPermissions(count = 1)

                val exception =
                    assertThrows<UnauthorizedException> {
                        service.grantPermission(
                            targetUserId = TARGET_USER_ID,
                            snippetId = SNIPPET_ID,
                            permissionToGrant = READ,
                            requestingUserId = OWNER_ID,
                        )
                    }

                assertEquals(
                    "User $OWNER_ID has no permissions on snippet $SNIPPET_ID to grant access.",
                    exception.message,
                )
                verify(repository, never()).save(any())
            }

            @Test
            @DisplayName("should reject when user only has READ permission")
            fun `rejects when user has only read permission`() {
                givenUserHasPermission(OWNER_ID, readerPermission(userId = OWNER_ID))

                val exception =
                    assertThrows<UnauthorizedException> {
                        service.grantPermission(
                            targetUserId = TARGET_USER_ID,
                            snippetId = SNIPPET_ID,
                            permissionToGrant = READ,
                            requestingUserId = OWNER_ID,
                        )
                    }

                assertEquals(
                    "User $OWNER_ID does not have WRITE permission to grant access.",
                    exception.message,
                )
            }
        }

        @Nested
        @DisplayName("when target user already has permission")
        inner class DuplicatePermissionScenarios {
            @Test
            @DisplayName("should reject duplicate permission grant")
            fun `rejects duplicate permission`() {
                givenUserHasPermission(OWNER_ID, ownerPermission())
                givenUserHasPermission(TARGET_USER_ID, readerPermission())

                val exception =
                    assertThrows<PermissionAlreadyExistsException> {
                        service.grantPermission(
                            targetUserId = TARGET_USER_ID,
                            snippetId = SNIPPET_ID,
                            permissionToGrant = WRITE,
                            requestingUserId = OWNER_ID,
                        )
                    }

                assertEquals(
                    "User $TARGET_USER_ID already has a permission on snippet $SNIPPET_ID",
                    exception.message,
                )
            }
        }
    }

    @Nested
    @DisplayName("deleteSnippet")
    inner class DeleteSnippetTests {
        @Nested
        @DisplayName("when owner deletes snippet")
        inner class ValidDeleteScenarios {
            @Test
            @DisplayName("should successfully delete all permissions")
            fun `deletes all permissions`() {
                givenUserHasPermission(OWNER_ID, ownerPermission())

                service.deleteSnippet(
                    snippetId = SNIPPET_ID,
                    requestingUserId = OWNER_ID,
                )

                verify(repository).deleteAllBySnippetId(SNIPPET_ID)
            }
        }

        @Nested
        @DisplayName("when delete is invalid")
        inner class InvalidDeleteScenarios {
            @Test
            @DisplayName("should reject when requesting user lacks WRITE permission")
            fun `rejects when requester lacks write`() {
                givenUserHasPermission(OWNER_ID, readerPermission(userId = OWNER_ID))

                val exception =
                    assertThrows<UnauthorizedException> {
                        service.deleteSnippet(
                            snippetId = SNIPPET_ID,
                            requestingUserId = OWNER_ID,
                        )
                    }

                assertEquals(
                    "User $OWNER_ID does not have WRITE permission on snippet $SNIPPET_ID",
                    exception.message,
                )
            }

            @Test
            @DisplayName("should reject when requesting user has no permission")
            fun `rejects when requester has no permission`() {
                givenUserHasNoPermission(OWNER_ID)

                val exception =
                    assertThrows<UnauthorizedException> {
                        service.deleteSnippet(
                            snippetId = SNIPPET_ID,
                            requestingUserId = OWNER_ID,
                        )
                    }

                assertEquals(
                    "User $OWNER_ID does not have WRITE permission on snippet $SNIPPET_ID",
                    exception.message,
                )
            }
        }
    }

    @Nested
    @DisplayName("hasPermission")
    inner class HasPermissionTests {
        @Test
        @DisplayName("should return true when user has exact permission")
        fun `returns true for exact permission`() {
            givenUserHasPermission(OWNER_ID, ownerPermission())
            val result = service.hasPermission(OWNER_ID, SNIPPET_ID, WRITE)
            assertEquals(true, result)
        }

        @Test
        @DisplayName("should return true when user has higher permission")
        fun `returns true for higher permission`() {
            givenUserHasPermission(OWNER_ID, ownerPermission())
            val result = service.hasPermission(OWNER_ID, SNIPPET_ID, READ)
            assertEquals(true, result)
        }

        @Test
        @DisplayName("should return false when user lacks permission")
        fun `returns false when user lacks permission`() {
            givenUserHasPermission(TARGET_USER_ID, readerPermission())
            val result = service.hasPermission(TARGET_USER_ID, SNIPPET_ID, WRITE)
            assertEquals(false, result)
        }

        @Test
        @DisplayName("should return false when user has no permission")
        fun `returns false when no permission`() {
            givenUserHasNoPermission(TARGET_USER_ID)
            val result = service.hasPermission(TARGET_USER_ID, SNIPPET_ID, READ)
            assertEquals(false, result)
        }
    }

    @Nested
    @DisplayName("getPermissionsForSnippet")
    inner class GetPermissionsForSnippetTests {
        @Test
        @DisplayName("should return all permissions when user has WRITE access")
        fun `returns all permissions for owner`() {
            val ownerPerm = ownerPermission()
            val readerPerm = readerPermission()
            val allPermissions = listOf(ownerPerm, readerPerm)

            givenUserHasPermission(OWNER_ID, ownerPerm)
            `when`(repository.findAllBySnippetId(SNIPPET_ID)).thenReturn(allPermissions)
            givenEmailLookup(OWNER_ID, "owner@example.com")
            givenEmailLookup(TARGET_USER_ID, "target@example.com")

            val result = service.getPermissionsForSnippet(SNIPPET_ID, OWNER_ID)

            assertEquals(2, result.size)
            assertEquals("owner@example.com", result[0].userEmail)
            assertEquals("target@example.com", result[1].userEmail)
        }

        @Test
        @DisplayName("should return empty list for snippet with no permissions")
        fun `returns empty list when no permissions`() {
            givenUserHasPermission(OWNER_ID, ownerPermission())
            `when`(repository.findAllBySnippetId(SNIPPET_ID)).thenReturn(emptyList())

            val result = service.getPermissionsForSnippet(SNIPPET_ID, OWNER_ID)

            assertEquals(0, result.size)
        }

        @Test
        @DisplayName("should reject when user only has READ permission")
        fun `rejects read-only user`() {
            givenUserHasPermission(OWNER_ID, readerPermission(userId = OWNER_ID))

            val exception =
                assertThrows<UnauthorizedException> {
                    service.getPermissionsForSnippet(SNIPPET_ID, OWNER_ID)
                }

            assertEquals(
                "User $OWNER_ID does not have WRITE permission on snippet $SNIPPET_ID",
                exception.message,
            )
        }

        @Test
        @DisplayName("should reject when user has no permission")
        fun `rejects user without permission`() {
            givenUserHasNoPermission(OWNER_ID)

            val exception =
                assertThrows<UnauthorizedException> {
                    service.getPermissionsForSnippet(SNIPPET_ID, OWNER_ID)
                }

            assertEquals(
                "User $OWNER_ID does not have WRITE permission on snippet $SNIPPET_ID",
                exception.message,
            )
        }

        @Test
        @DisplayName("should map entity permissions to DTOs correctly")
        fun `maps permissions to dtos correctly`() {
            val ownerPerm = ownerPermission()
            val readerPerm = readerPermission()
            val allPermissions = listOf(ownerPerm, readerPerm)

            givenUserHasPermission(OWNER_ID, ownerPerm)
            `when`(repository.findAllBySnippetId(SNIPPET_ID)).thenReturn(allPermissions)
            givenEmailLookup(OWNER_ID, "owner@example.com")
            givenEmailLookup(TARGET_USER_ID, "target@example.com")

            val result = service.getPermissionsForSnippet(SNIPPET_ID, OWNER_ID)

            assertEquals(2, result.size)

            val ownerDto = result[0]
            assertEquals(ownerPerm.id, ownerDto.id)
            assertEquals(ownerPerm.snippetId, ownerDto.snippetId)
            assertEquals(ownerPerm.userId, ownerDto.userId)
            assertEquals("owner@example.com", ownerDto.userEmail)
            assertEquals(ownerPerm.permission, ownerDto.permission)

            val readerDto = result[1]
            assertEquals(readerPerm.id, readerDto.id)
            assertEquals(readerPerm.snippetId, readerDto.snippetId)
            assertEquals(readerPerm.userId, readerDto.userId)
            assertEquals("target@example.com", readerDto.userEmail)
            assertEquals(readerPerm.permission, readerDto.permission)
        }

        @Test
        @DisplayName("should fetch email for each permission in list")
        fun `fetches email for each permission`() {
            val ownerPerm = ownerPermission()
            val readerPerm = readerPermission()
            val allPermissions = listOf(ownerPerm, readerPerm)

            givenUserHasPermission(OWNER_ID, ownerPerm)
            `when`(repository.findAllBySnippetId(SNIPPET_ID)).thenReturn(allPermissions)
            givenEmailLookup(OWNER_ID, "owner@example.com")
            givenEmailLookup(TARGET_USER_ID, "target@example.com")

            service.getPermissionsForSnippet(SNIPPET_ID, OWNER_ID)

            verify(auth0ManagementService).getUserEmail(OWNER_ID)
            verify(auth0ManagementService).getUserEmail(TARGET_USER_ID)
        }
    }

    // Helper methods - DSL Style
    private fun givenUserHasPermission(
        userId: String,
        permission: SnippetsAuthorization,
    ) {
        `when`(repository.findByUserIdAndSnippetId(userId, SNIPPET_ID))
            .thenReturn(Optional.of(permission))
    }

    private fun givenUserHasNoPermission(userId: String) {
        `when`(repository.findByUserIdAndSnippetId(userId, SNIPPET_ID))
            .thenReturn(Optional.empty())
    }

    private fun givenNoPermissionsExist() {
        `when`(repository.findByUserIdAndSnippetId(any(), any()))
            .thenReturn(Optional.empty())
    }

    private fun givenSnippetHasNoPermissions() {
        `when`(repository.countBySnippetId(SNIPPET_ID)).thenReturn(0L)
    }

    private fun givenSnippetHasExistingPermissions(count: Long) {
        `when`(repository.countBySnippetId(SNIPPET_ID)).thenReturn(count)
    }

    private fun givenSaveReturnsInput() {
        `when`(repository.save(any<SnippetsAuthorization>())).thenAnswer { it.arguments[0] }
    }

    private fun givenEmailLookup(
        userId: String,
        email: String,
    ) {
        `when`(auth0ManagementService.getUserEmail(userId)).thenReturn(email)
    }
}
