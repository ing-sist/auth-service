package ingsist.auth.controller

import ingsist.auth.dto.GrantPermissionDto
import ingsist.auth.entity.SnippetsAuthorization
import ingsist.auth.service.AuthorizationService
import org.springframework.http.ResponseEntity
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/snippets")
class SnippetAuthorizationController(private val authorizationService: AuthorizationService) {

    /**
     * Compartir un snippet (Otorgar permiso)
     * POST /snippets/{snippetId}/permissions
     *
     * Crea un nuevo recurso de "permiso" para un snippet.
     * El 'requestingUserId' (quien comparte) se obtiene del token.
     * El 'targetUserId' (a quien se comparte) viene en el body.
     */
    @PostMapping("/{snippetId}/permissions")
    fun grantPermission(
        @PathVariable snippetId: String,
        @RequestBody request: GrantPermissionDto,
        @AuthenticationPrincipal jwt: Jwt,
    ): ResponseEntity<SnippetsAuthorization> {
        val requestingUserId = jwt.subject
        val targetUserId = request.userId

        val newPermission = authorizationService.grantPermission(
            targetUserId = targetUserId,
            snippetId = snippetId,
            permissionToGrant = request.permission,
            requestingUserId = requestingUserId,
        )
        // Devuelve 201 Created con el recurso creado
        return ResponseEntity.status(201).body(newPermission)
    }

    /**
     * Revocar el permiso de un usuario sobre un snippet.
     * DELETE /snippets/{snippetId}/permissions/{userId}
     *
     * Elimina un recurso de "permiso" específico.
     * El 'requestingUserId' (quien revoca) se obtiene del token.
     * El 'targetUserId' (a quien se revoca) viene en la URL.
     */
    @DeleteMapping("/{snippetId}/permissions/{userId}")
    fun revokePermission(
        @PathVariable snippetId: String,
        @PathVariable("userId") targetUserId: String,
        @AuthenticationPrincipal jwt: Jwt,
    ): ResponseEntity<Unit> {
        val requestingUserId = jwt.subject

        authorizationService.revokePermission(
            targetUserId = targetUserId,
            snippetId = snippetId,
            requestingUserId = requestingUserId,
        )
        // Devuelve 204 No Content
        return ResponseEntity.noContent().build()
    }

    /**
     * Obtener un permiso específico.
     * GET /snippets/{snippetId}/permissions/{userId}
     *
     * Obtiene un recurso de "permiso" específico.
     * Si no existe, el 'GlobalExceptionHandler' devolverá 404 Not Found.
     * Esto permite al Snippet-Service verificar un permiso con un simple GET.
     */
    @GetMapping("/{snippetId}/permissions/{userId}")
    fun getPermissionForUserOnSnippet(
        @PathVariable snippetId: String,
        @PathVariable("userId") targetUserId: String,
        @AuthenticationPrincipal jwt: Jwt,
    ): ResponseEntity<SnippetsAuthorization> {
        val permission = authorizationService.getPermission(targetUserId, snippetId)
        return ResponseEntity.ok(permission)
    }

    /**
     * Listar todos los permisos de un snippet.
     * GET /snippets/{snippetId}/permissions
     */
    @GetMapping("/{snippetId}/permissions")
    fun getPermissionsForSnippet(
        @PathVariable snippetId: String,
        @AuthenticationPrincipal jwt: Jwt,
    ): ResponseEntity<List<SnippetsAuthorization>> {
        val requestingUserId = jwt.subject

        val permissions = authorizationService.getPermissionsForSnippet(snippetId, requestingUserId)
        return ResponseEntity.ok(permissions)
    }
}
