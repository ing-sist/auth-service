package ingsist.auth.service

import ingsist.auth.entity.AuthorizationTypes
import ingsist.auth.entity.AuthorizationTypes.READ
import ingsist.auth.entity.AuthorizationTypes.WRITE
import ingsist.auth.entity.SnippetsAuthorization
import ingsist.auth.exceptions.CannotRevokeLastWritePermissionException
import ingsist.auth.exceptions.PermissionAlreadyExistsException
import ingsist.auth.exceptions.PermissionNotFoundException
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
@DisplayName("AuthorizationService")
class AuthorizationServiceTest {
    @Mock
    private lateinit var repository: SnippetAuthorizationRepository

    @InjectMocks
    private lateinit var service: AuthorizationService

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
    @DisplayName("revokePermission")
    inner class RevokePermissionTests {
        @Nested
        @DisplayName("when owner revokes permission")
        inner class ValidRevokeScenarios {
            @Test
            @DisplayName("should successfully revoke READ permission")
            fun `revokes read permission`() {
                val targetPermission = readerPermission()
                givenUserHasPermission(OWNER_ID, ownerPermission())
                givenUserHasPermission(TARGET_USER_ID, targetPermission)

                service.revokePermission(
                    targetUserId = TARGET_USER_ID,
                    snippetId = SNIPPET_ID,
                    requestingUserId = OWNER_ID,
                )

                verify(repository).delete(targetPermission)
            }

            @Test
            @DisplayName("should revoke WRITE permission when multiple writers exist")
            fun `revokes write when multiple writers exist`() {
                val targetPermission =
                    aPermission(
                        id = "target-perm",
                        userId = TARGET_USER_ID,
                        permission = WRITE,
                    )
                givenUserHasPermission(OWNER_ID, ownerPermission())
                givenUserHasPermission(TARGET_USER_ID, targetPermission)
                givenWritePermissionCount(count = 2)

                service.revokePermission(
                    targetUserId = TARGET_USER_ID,
                    snippetId = SNIPPET_ID,
                    requestingUserId = OWNER_ID,
                )

                verify(repository).delete(targetPermission)
            }
        }

        @Nested
        @DisplayName("when revoke is invalid")
        inner class InvalidRevokeScenarios {
            @Test
            @DisplayName("should reject when target permission does not exist")
            fun `rejects when permission not found`() {
                givenUserHasPermission(OWNER_ID, ownerPermission())
                givenUserHasNoPermission(TARGET_USER_ID)

                val exception =
                    assertThrows<PermissionNotFoundException> {
                        service.revokePermission(
                            targetUserId = TARGET_USER_ID,
                            snippetId = SNIPPET_ID,
                            requestingUserId = OWNER_ID,
                        )
                    }

                assertEquals(
                    "No permission found for user $TARGET_USER_ID on snippet $SNIPPET_ID",
                    exception.message,
                )
            }

            @Test
            @DisplayName("should reject when revoking last WRITE permission")
            fun `rejects revoking last write permission`() {
                val targetPermission =
                    aPermission(
                        id = "target-perm",
                        userId = TARGET_USER_ID,
                        permission = WRITE,
                    )
                givenUserHasPermission(OWNER_ID, ownerPermission())
                givenUserHasPermission(TARGET_USER_ID, targetPermission)
                givenWritePermissionCount(count = 1)

                val exception =
                    assertThrows<CannotRevokeLastWritePermissionException> {
                        service.revokePermission(
                            targetUserId = TARGET_USER_ID,
                            snippetId = SNIPPET_ID,
                            requestingUserId = OWNER_ID,
                        )
                    }

                assertEquals(
                    "Cannot revoke the last WRITE permission for snippet $SNIPPET_ID",
                    exception.message,
                )
            }

            @Test
            @DisplayName("should reject when requesting user lacks WRITE permission")
            fun `rejects when requester lacks write`() {
                givenUserHasPermission(OWNER_ID, readerPermission(userId = OWNER_ID))

                val exception =
                    assertThrows<UnauthorizedException> {
                        service.revokePermission(
                            targetUserId = TARGET_USER_ID,
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
                        service.revokePermission(
                            targetUserId = TARGET_USER_ID,
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
    @DisplayName("checkPermission")
    inner class CheckPermissionTests {
        @Nested
        @DisplayName("when user has sufficient permission")
        inner class SufficientPermission {
            @Test
            @DisplayName("should pass when WRITE user checks for READ")
            fun `write satisfies read requirement`() {
                givenUserHasPermission(OWNER_ID, ownerPermission())

                // Should not throw
                service.checkPermission(OWNER_ID, SNIPPET_ID, READ)
            }

            @Test
            @DisplayName("should pass when WRITE user checks for WRITE")
            fun `write satisfies write requirement`() {
                givenUserHasPermission(OWNER_ID, ownerPermission())

                service.checkPermission(OWNER_ID, SNIPPET_ID, WRITE)
            }

            @Test
            @DisplayName("should pass when READ user checks for READ")
            fun `read satisfies read requirement`() {
                givenUserHasPermission(OWNER_ID, readerPermission(userId = OWNER_ID))

                service.checkPermission(OWNER_ID, SNIPPET_ID, READ)
            }
        }

        @Nested
        @DisplayName("when user lacks permission")
        inner class InsufficientPermission {
            @Test
            @DisplayName("should reject when READ user checks for WRITE")
            fun `read does not satisfy write requirement`() {
                givenUserHasPermission(OWNER_ID, readerPermission(userId = OWNER_ID))

                val exception =
                    assertThrows<UnauthorizedException> {
                        service.checkPermission(OWNER_ID, SNIPPET_ID, WRITE)
                    }

                assertEquals(
                    "User $OWNER_ID does not have WRITE permission on snippet $SNIPPET_ID",
                    exception.message,
                )
            }

            @Test
            @DisplayName("should reject when user has no permission and checks for READ")
            fun `no permission fails read check`() {
                givenUserHasNoPermission(OWNER_ID)

                val exception =
                    assertThrows<UnauthorizedException> {
                        service.checkPermission(OWNER_ID, SNIPPET_ID, READ)
                    }

                assertEquals(
                    "User $OWNER_ID does not have READ permission on snippet $SNIPPET_ID",
                    exception.message,
                )
            }

            @Test
            @DisplayName("should reject when user has no permission and checks for WRITE")
            fun `no permission fails write check`() {
                givenUserHasNoPermission(OWNER_ID)

                val exception =
                    assertThrows<UnauthorizedException> {
                        service.checkPermission(OWNER_ID, SNIPPET_ID, WRITE)
                    }

                assertEquals(
                    "User $OWNER_ID does not have WRITE permission on snippet $SNIPPET_ID",
                    exception.message,
                )
            }
        }
    }

    @Nested
    @DisplayName("getPermission")
    inner class GetPermissionTests {
        @Test
        @DisplayName("should return permission when it exists")
        fun `returns existing permission`() {
            val expectedPermission = readerPermission()
            givenUserHasPermission(TARGET_USER_ID, expectedPermission)

            val result = service.getPermission(TARGET_USER_ID, SNIPPET_ID)

            assertEquals(expectedPermission, result)
            assertEquals(READ, result.permission)
        }

        @Test
        @DisplayName("should throw PermissionNotFoundException when permission does not exist")
        fun `throws when permission not found`() {
            givenUserHasNoPermission(TARGET_USER_ID)

            val exception =
                assertThrows<PermissionNotFoundException> {
                    service.getPermission(TARGET_USER_ID, SNIPPET_ID)
                }

            assertEquals(
                "No permission found for user $TARGET_USER_ID on snippet $SNIPPET_ID",
                exception.message,
            )
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

            val result = service.getPermissionsForSnippet(SNIPPET_ID, OWNER_ID)

            assertEquals(2, result.size)
            assertEquals(allPermissions, result)
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

    private fun givenWritePermissionCount(count: Long) {
        `when`(repository.countBySnippetIdAndPermission(SNIPPET_ID, WRITE)).thenReturn(count)
    }

    private fun givenSaveReturnsInput() {
        `when`(repository.save(any<SnippetsAuthorization>())).thenAnswer { it.arguments[0] }
    }
}
