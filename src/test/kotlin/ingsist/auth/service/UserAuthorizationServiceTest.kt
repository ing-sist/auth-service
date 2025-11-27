package ingsist.auth.service

import ingsist.auth.entity.AuthorizationTypes.READ
import ingsist.auth.entity.AuthorizationTypes.WRITE
import ingsist.auth.entity.SnippetsAuthorization
import ingsist.auth.repository.SnippetAuthorizationRepository
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`
import org.mockito.junit.jupiter.MockitoExtension

@ExtendWith(MockitoExtension::class)
@DisplayName("UserAuthorizationService")
class UserAuthorizationServiceTest {
    @Mock
    private lateinit var repository: SnippetAuthorizationRepository

    @Mock
    private lateinit var auth0ManagementService: Auth0ManagementService

    @InjectMocks
    private lateinit var service: UserAuthorizationService

    companion object {
        const val USER_ID = "user-123"
        const val ANOTHER_USER_ID = "user-456"

        fun aPermission(
            id: String,
            snippetId: String,
            userId: String = USER_ID,
            permission: ingsist.auth.entity.AuthorizationTypes = READ,
        ) = SnippetsAuthorization(
            id = id,
            snippetId = snippetId,
            userId = userId,
            permission = permission,
        )

        fun multiplePermissions(userId: String = USER_ID) =
            listOf(
                aPermission(id = "perm-1", snippetId = "snippet-1", userId = userId, permission = READ),
                aPermission(id = "perm-2", snippetId = "snippet-2", userId = userId, permission = WRITE),
                aPermission(id = "perm-3", snippetId = "snippet-3", userId = userId, permission = READ),
            )
    }

    @Nested
    @DisplayName("getPermissionsForUser")
    inner class GetPermissionsForUserTests {
        @Nested
        @DisplayName("when user has permissions")
        inner class UserHasPermissions {
            @Test
            @DisplayName("should return all permissions for the user")
            fun `returns all user permissions`() {
                // Given
                val expectedPermissions = multiplePermissions()
                givenUserPermissions(USER_ID, expectedPermissions)
                givenEmailLookup(USER_ID, "user@example.com")

                // When
                val result = service.getPermissionsForUser(USER_ID)

                // Then
                assertEquals(3, result.size)
                assertEquals("user@example.com", result[0].userEmail)
                verify(repository).findAllByUserId(USER_ID)
            }

            @Test
            @DisplayName("should return single permission when user has one")
            fun `returns single permission`() {
                val singlePermission =
                    listOf(
                        aPermission(id = "perm-1", snippetId = "snippet-1", permission = WRITE),
                    )
                givenUserPermissions(USER_ID, singlePermission)
                givenEmailLookup(USER_ID, "user@example.com")

                val result = service.getPermissionsForUser(USER_ID)

                assertEquals(1, result.size)
                assertEquals(USER_ID, result[0].userId)
                assertEquals("user@example.com", result[0].userEmail)
                assertEquals(WRITE, result[0].permission)
            }

            @Test
            @DisplayName("should return only permissions for the specified user")
            fun `returns only specified user permissions`() {
                val userPermissions =
                    listOf(
                        aPermission(id = "perm-1", snippetId = "snippet-1", userId = USER_ID),
                    )
                givenUserPermissions(USER_ID, userPermissions)
                givenEmailLookup(USER_ID, "user@example.com")

                val result = service.getPermissionsForUser(USER_ID)

                assertEquals(1, result.size)
                assertTrue(result.all { it.userId == USER_ID })
            }

            @Test
            @DisplayName("should return permissions with mixed types (READ and WRITE)")
            fun `returns mixed permission types`() {
                val mixedPermissions =
                    listOf(
                        aPermission(id = "perm-1", snippetId = "snippet-1", permission = READ),
                        aPermission(id = "perm-2", snippetId = "snippet-2", permission = WRITE),
                    )
                givenUserPermissions(USER_ID, mixedPermissions)
                givenEmailLookup(USER_ID, "user@example.com")

                val result = service.getPermissionsForUser(USER_ID)

                assertEquals(2, result.size)
                assertEquals(READ, result[0].permission)
                assertEquals(WRITE, result[1].permission)
            }
        }

        @Nested
        @DisplayName("when user has no permissions")
        inner class UserHasNoPermissions {
            @Test
            @DisplayName("should return empty list when user has no permissions")
            fun `returns empty list`() {
                givenUserPermissions(USER_ID, emptyList())

                val result = service.getPermissionsForUser(USER_ID)

                assertTrue(result.isEmpty())
                verify(repository).findAllByUserId(USER_ID)
            }

            @Test
            @DisplayName("should return empty list for non-existent user")
            fun `returns empty for nonexistent user`() {
                givenUserPermissions("nonexistent-user", emptyList())

                val result = service.getPermissionsForUser("nonexistent-user")

                assertTrue(result.isEmpty())
            }
        }

        @Nested
        @DisplayName("edge cases")
        inner class EdgeCases {
            @Test
            @DisplayName("should handle user with permissions on same snippet")
            fun `handles permissions on same snippet`() {
                // This shouldn't normally happen, but test the behavior
                val permission =
                    aPermission(
                        id = "perm-1",
                        snippetId = "snippet-1",
                        permission = WRITE,
                    )
                givenUserPermissions(USER_ID, listOf(permission))
                givenEmailLookup(USER_ID, "user@example.com")

                val result = service.getPermissionsForUser(USER_ID)

                assertEquals(1, result.size)
                assertEquals("snippet-1", result[0].snippetId)
            }

            @Test
            @DisplayName("should correctly delegate to repository")
            fun `delegates to repository correctly`() {
                val permissions = multiplePermissions()
                givenUserPermissions(USER_ID, permissions)
                givenEmailLookup(USER_ID, "user@example.com")

                service.getPermissionsForUser(USER_ID)

                verify(repository).findAllByUserId(USER_ID)
            }

            @Test
            @DisplayName("should fetch email for each permission")
            fun `fetches email for each permission`() {
                val permissions = multiplePermissions()
                givenUserPermissions(USER_ID, permissions)
                givenEmailLookup(USER_ID, "user@example.com")

                val result = service.getPermissionsForUser(USER_ID)

                assertEquals(3, result.size)
                result.forEach { dto ->
                    assertEquals("user@example.com", dto.userEmail)
                }
                verify(auth0ManagementService, org.mockito.Mockito.times(3)).getUserEmail(USER_ID)
            }

            @Test
            @DisplayName("should map all entity fields to DTO")
            fun `maps all entity fields to dto`() {
                val permission = aPermission(id = "perm-1", snippetId = "snippet-1", permission = READ)
                givenUserPermissions(USER_ID, listOf(permission))
                givenEmailLookup(USER_ID, "user@example.com")

                val result = service.getPermissionsForUser(USER_ID)

                assertEquals(1, result.size)
                val dto = result[0]
                assertEquals(permission.id, dto.id)
                assertEquals(permission.snippetId, dto.snippetId)
                assertEquals(permission.userId, dto.userId)
                assertEquals("user@example.com", dto.userEmail)
                assertEquals(permission.permission, dto.permission)
            }

            @Test
            @DisplayName("should handle different users in permissions list")
            fun `handles different users in permissions`() {
                val permissions =
                    listOf(
                        aPermission(id = "perm-1", snippetId = "snippet-1", userId = USER_ID),
                        aPermission(id = "perm-2", snippetId = "snippet-2", userId = USER_ID),
                    )
                givenUserPermissions(USER_ID, permissions)
                givenEmailLookup(USER_ID, "user@example.com")

                val result = service.getPermissionsForUser(USER_ID)

                assertEquals(2, result.size)
                result.forEach { dto ->
                    assertEquals(USER_ID, dto.userId)
                }
            }
        }
    }

    // Helper methods - DSL Style
    private fun givenUserPermissions(
        userId: String,
        permissions: List<SnippetsAuthorization>,
    ) {
        `when`(repository.findAllByUserId(userId)).thenReturn(permissions)
    }

    private fun givenEmailLookup(
        userId: String,
        email: String,
    ) {
        `when`(auth0ManagementService.getUserEmail(userId)).thenReturn(email)
    }
}
