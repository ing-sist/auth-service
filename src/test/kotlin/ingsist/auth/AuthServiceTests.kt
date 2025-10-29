package ingsist.auth

import ingsist.auth.entity.AuthorizationTypes
import ingsist.auth.entity.SnippetsAuthorization
import ingsist.auth.exceptions.CannotRevokeLastWritePermissionException
import ingsist.auth.exceptions.PermissionAlreadyExistsException
import ingsist.auth.exceptions.PermissionNotFoundException
import ingsist.auth.exceptions.UnauthorizedException
import ingsist.auth.repository.SnippetAuthorizationRepository
import ingsist.auth.service.AuthorizationService
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
import io.mockk.verify
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.Optional

class AuthServiceTests {
    private val repository: SnippetAuthorizationRepository = mockk()
    private val service = AuthorizationService(repository)

    private val snippetId = "snippet1"
    private val ownerId = "user-owner"
    private val collaboratorId = "user-collaborator"
    private val strangerId = "user-stranger"

    @Test
    fun `checkPermission should pass when user has required permission`() {
        every { repository.findByUserIdAndSnippetId(ownerId, snippetId) } returns
            Optional.of(
                SnippetsAuthorization(
                    userId = ownerId,
                    snippetId = snippetId,
                    permission = AuthorizationTypes.WRITE,
                ),
            )

        assertDoesNotThrow {
            service.checkPermission(ownerId, snippetId, AuthorizationTypes.WRITE)
            service.checkPermission(ownerId, snippetId, AuthorizationTypes.READ)
        }
    }

    @Test
    fun `checkPermission should fail when user permission is insufficient`() {
        every { repository.findByUserIdAndSnippetId(collaboratorId, snippetId) } returns
            Optional.of(
                SnippetsAuthorization(
                    userId = collaboratorId,
                    snippetId = snippetId,
                    permission = AuthorizationTypes.READ,
                ),
            )

        assertThrows<UnauthorizedException> {
            service.checkPermission(collaboratorId, snippetId, AuthorizationTypes.WRITE)
        }
    }

    @Test
    fun `grantPermission should succeed for the FIRST permission on a snippet (implicit owner creation)`() {
        // Arrange: El solicitante será el nuevo dueño. No tiene permisos previos.
        every { repository.findByUserIdAndSnippetId(ownerId, snippetId) } returns Optional.empty()
        // Arrange: El repositorio reporta que NO existen permisos para este snippet.
        every { repository.countBySnippetId(snippetId) } returns 0L
        // Arrange: El guardado funcionará.
        every { repository.save(any()) } returns mockk()

        // Act & Assert: Se debe poder otorgar WRITE a sí mismo como primer permiso.
        assertDoesNotThrow {
            service.grantPermission(
                ownerId,
                snippetId,
                AuthorizationTypes.WRITE,
                ownerId,
            )
        }
        verify(exactly = 1) { repository.save(any()) }
    }

    @Test
    fun `grantPermission should succeed when an existing owner grants permission to another user`() {
        // Arrange: El solicitante (ownerId) tiene permiso de WRITE.
        every { repository.findByUserIdAndSnippetId(ownerId, snippetId) } returns
            Optional.of(
                SnippetsAuthorization(
                    userId = ownerId,
                    snippetId =
                    snippetId,
                    permission = AuthorizationTypes.WRITE,
                ),
            )
        // Arrange: El usuario objetivo (collaboratorId) no tiene permisos aún.
        every { repository.findByUserIdAndSnippetId(collaboratorId, snippetId) } returns Optional.empty()
        // Arrange: El guardado funcionará.
        every { repository.save(any()) } returns mockk()

        // Act & Assert
        assertDoesNotThrow {
            service.grantPermission(
                collaboratorId,
                snippetId,
                AuthorizationTypes.READ,
                ownerId,
            )
        }
        verify(exactly = 1) { repository.save(any()) }
    }

    @Test
    fun `grantPermission should fail if requester has no permission and other permissions already exist`() {
        // Arrange: El solicitante (strangerId) no tiene permisos.
        every { repository.findByUserIdAndSnippetId(strangerId, snippetId) } returns Optional.empty()
        // Arrange: Ya existen otros permisos para este snippet.
        every { repository.countBySnippetId(snippetId) } returns 1L

        // Act & Assert
        assertThrows<UnauthorizedException> {
            service.grantPermission(
                collaboratorId,
                snippetId,
                AuthorizationTypes.READ,
                strangerId,
            )
        }
    }

    @Test
    fun `grantPermission should fail if target user already has a permission`() {
        // Arrange: El solicitante tiene WRITE.
        every { repository.findByUserIdAndSnippetId(ownerId, snippetId) } returns
            Optional.of(
                SnippetsAuthorization(
                    userId = ownerId,
                    snippetId =
                    snippetId,
                    permission = AuthorizationTypes.WRITE,
                ),
            )
        // Arrange: El usuario objetivo ya tiene un permiso.
        every { repository.findByUserIdAndSnippetId(collaboratorId, snippetId) } returns
            Optional.of(
                SnippetsAuthorization(
                    userId = collaboratorId,
                    snippetId =
                    snippetId,
                    permission = AuthorizationTypes.READ,
                ),
            )

        // Act & Assert
        assertThrows<PermissionAlreadyExistsException> {
            service.grantPermission(
                collaboratorId,
                snippetId,
                AuthorizationTypes.WRITE,
                ownerId,
            )
        }
    }

    @Test
    fun `revokePermission should succeed when owner revokes a collaborator's permission`() {
        // Arrange: El solicitante (owner) tiene WRITE.
        every { repository.findByUserIdAndSnippetId(ownerId, snippetId) } returns
            Optional.of(
                SnippetsAuthorization(
                    userId = ownerId,
                    snippetId =
                    snippetId,
                    permission = AuthorizationTypes.WRITE,
                ),
            )
        // Arrange: El permiso del colaborador a revocar existe.
        val permissionToRevoke =
            SnippetsAuthorization(
                userId = collaboratorId,
                snippetId =
                snippetId,
                permission = AuthorizationTypes.READ,
            )
        every { repository.findByUserIdAndSnippetId(collaboratorId, snippetId) } returns
            Optional.of(permissionToRevoke)
        // Arrange: El método delete no lanzará excepciones.
        every { repository.delete(permissionToRevoke) } just runs

        // Act & Assert
        assertDoesNotThrow {
            service.revokePermission(collaboratorId, snippetId, ownerId)
        }
        verify(exactly = 1) { repository.delete(permissionToRevoke) }
    }

    @Test
    fun `revokePermission should fail when trying to revoke the last WRITE permission`() {
        // Arrange: El solicitante (owner) tiene WRITE.
        val ownerPermission =
            SnippetsAuthorization(
                userId = ownerId,
                snippetId = snippetId,
                permission = AuthorizationTypes.WRITE,
            )
        every { repository.findByUserIdAndSnippetId(ownerId, snippetId) } returns
            Optional.of(ownerPermission)
        // Arrange: El repositorio reporta que solo hay 1 escritor.
        every { repository.countBySnippetIdAndPermission(snippetId, AuthorizationTypes.WRITE) } returns 1L

        // Act & Assert
        assertThrows<CannotRevokeLastWritePermissionException> {
            service.revokePermission(ownerId, snippetId, ownerId)
        }
    }

    @Test
    fun `revokePermission should fail if permission to revoke is not found`() {
        // Arrange: El solicitante (owner) tiene WRITE.
        every { repository.findByUserIdAndSnippetId(ownerId, snippetId) } returns
            Optional.of(
                SnippetsAuthorization(
                    userId = ownerId,
                    snippetId = snippetId,
                    permission = AuthorizationTypes.WRITE,
                ),
            )
        // Arrange: El permiso a revocar no existe.
        every { repository.findByUserIdAndSnippetId(strangerId, snippetId) } returns Optional.empty()

        // Act & Assert
        assertThrows<PermissionNotFoundException> {
            service.revokePermission(strangerId, snippetId, ownerId)
        }
    }
}
