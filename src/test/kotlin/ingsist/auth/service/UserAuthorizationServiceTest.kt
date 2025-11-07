package ingsist.auth.service

import ingsist.auth.entity.AuthorizationTypes
import ingsist.auth.entity.SnippetsAuthorization
import ingsist.auth.repository.SnippetAuthorizationRepository
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`
import org.mockito.junit.jupiter.MockitoExtension

@ExtendWith(MockitoExtension::class)
class UserAuthorizationServiceTest {
    @Mock
    private lateinit var repository: SnippetAuthorizationRepository

    @InjectMocks
    private lateinit var service: UserAuthorizationService

    @Test
    fun `getPermissionsForUser should return list of permissions for user`() {
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
                SnippetsAuthorization(
                    id = "perm-3",
                    snippetId = "snippet-3",
                    userId = userId,
                    permission = AuthorizationTypes.READ,
                ),
            )

        `when`(repository.findAllByUserId(userId))
            .thenReturn(expectedPermissions)

        val result = service.getPermissionsForUser(userId)

        assertEquals(expectedPermissions, result)
        assertEquals(3, result.size)
        verify(repository).findAllByUserId(userId)
    }

    @Test
    fun `getPermissionsForUser should return empty list when user has no permissions`() {
        val userId = "user123"
        val expectedPermissions = emptyList<SnippetsAuthorization>()

        `when`(repository.findAllByUserId(userId))
            .thenReturn(expectedPermissions)

        val result = service.getPermissionsForUser(userId)

        assertTrue(result.isEmpty())
        verify(repository).findAllByUserId(userId)
    }

    @Test
    fun `getPermissionsForUser should return only permissions for specified user`() {
        val userId = "user123"
        val expectedPermissions =
            listOf(
                SnippetsAuthorization(
                    id = "perm-1",
                    snippetId = "snippet-1",
                    userId = userId,
                    permission = AuthorizationTypes.WRITE,
                ),
            )

        `when`(repository.findAllByUserId(userId))
            .thenReturn(expectedPermissions)

        val result = service.getPermissionsForUser(userId)

        assertEquals(1, result.size)
        assertEquals(userId, result[0].userId)
    }
}
